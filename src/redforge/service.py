"""Core service surface for RedForge.

The frozen baseline only reports process health. Later work adds the real
capabilities described in README.md behind this module; keep the public
surface here backward compatible.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from . import __version__

MAX_RULES_PER_FIELD = 1000

SEVERITIES = ("info", "low", "medium", "high", "critical")
LOGICS = ("all", "any")
OPERATORS = ("equals", "contains", "regex")

_OBSERVATION_FIELDS = frozenset({"id", "target", "status", "headers", "body"})
_TEMPLATE_FIELDS = frozenset({"id", "name", "severity", "logic", "matchers"})

_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ScopeViolationError(Exception):
    """Raised when an observation target falls outside the authorized scope."""


def _normalize_hostname(name: str) -> str:
    """Lowercase IDNA ASCII form without a trailing dot; raise on bad syntax."""
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise ValueError("empty hostname")
    try:
        ascii_name = name.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"invalid hostname: {name!r}") from exc
    if len(ascii_name) > 253:
        raise ValueError(f"hostname too long: {name!r}")
    for label in ascii_name.split("."):
        if not _LABEL_RE.fullmatch(label):
            raise ValueError(f"invalid hostname: {name!r}")
    return ascii_name


@dataclass(frozen=True)
class _Entry:
    """A normalized rule or target.

    kind is one of "ip", "network", "host", "wildcard". text is the
    normalized representation; value is the parsed ip object for ip/network
    entries, or the normalized hostname (wildcard: the root hostname).
    """

    kind: str
    text: str
    value: Any


def _parse_entry(raw: object, *, allow_wildcard: bool) -> _Entry:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"entries must be non-empty strings, got {raw!r}")
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {raw!r}") from exc
        return _Entry("network", str(network), network)
    if raw.startswith("*."):
        if not allow_wildcard:
            raise ValueError(f"wildcard not allowed as target: {raw!r}")
        root = _normalize_hostname(raw[2:])
        return _Entry("wildcard", "*." + root, root)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        return _Entry("ip", str(address), address)
    hostname = _normalize_hostname(raw)
    return _Entry("host", hostname, hostname)


def _matches(rule: _Entry, target: _Entry) -> bool:
    """Whether a non-network target is covered by a rule."""
    if target.kind == "ip":
        if rule.kind == "ip":
            return rule.value == target.value
        if rule.kind == "network":
            return (
                rule.value.version == target.value.version
                and target.value in rule.value
            )
        return False
    if target.kind == "host":
        if rule.kind == "host":
            return rule.value == target.value
        if rule.kind == "wildcard":
            # Real subdomains only; the root domain itself does not match.
            return target.value != rule.value and target.value.endswith(
                "." + rule.value
            )
        return False
    return False


def _decision(
    original: str,
    normalized: str,
    allowed: bool,
    reason: str,
    matched_rule: str | None,
) -> dict[str, Any]:
    return {
        "original": original,
        "normalized": normalized,
        "allowed": allowed,
        "reason": reason,
        "matched_rule": matched_rule,
    }


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_fields(obj: object, fields: frozenset[str], what: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError(f"{what} must be an object")
    keys = set(obj)
    missing = fields - keys
    if missing:
        raise ValueError(f"{what} missing field: {sorted(missing)[0]}")
    extra = keys - fields
    if extra:
        raise ValueError(f"{what} has unknown field: {sorted(extra)[0]}")
    return obj


def _non_empty_str(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty string")
    return value


@dataclass(frozen=True)
class _Observation:
    """A validated HTTP observation.

    target is the parsed scope entry; its text attribute is the normalized
    form reported back in findings.
    """

    id: str
    target: _Entry
    status: int
    headers: dict[str, str]
    body: str


@dataclass(frozen=True)
class _Matcher:
    """A validated matcher.

    kind is one of "status", "header", "body". For status matchers value is
    a frozenset of integers; for header/body matchers value is the non-empty
    comparison string and regex holds the compiled pattern when the operator
    is "regex".
    """

    kind: str
    name: str | None
    operator: str | None
    value: Any
    regex: Any = None


@dataclass(frozen=True)
class _Template:
    id: str
    name: str
    severity: str
    logic: str
    matchers: list[_Matcher]


def _parse_matcher(raw: object, what: str) -> _Matcher:
    if not isinstance(raw, dict):
        raise ValueError(f"{what} must be an object")
    keys = set(raw)
    if keys == {"values"}:
        values = raw["values"]
        if not isinstance(values, list) or not values:
            raise ValueError(f"{what}.values must be a non-empty array")
        if any(not _is_int(item) for item in values):
            raise ValueError(f"{what}.values must contain only integers")
        return _Matcher("status", None, None, frozenset(values))
    if keys == {"name", "operator", "value"}:
        kind = "header"
        name = raw["name"]
        if not isinstance(name, str):
            raise ValueError(f"{what}.name must be a string")
    elif keys == {"operator", "value"}:
        kind = "body"
        name = None
    else:
        raise ValueError(f"{what} has unknown or missing fields")
    operator = raw["operator"]
    if operator not in OPERATORS:
        raise ValueError(f"{what}.operator must be one of {OPERATORS}")
    value = raw["value"]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what}.value must be a non-empty string")
    regex = None
    if operator == "regex":
        try:
            regex = re.compile(value)
        except re.error as exc:
            raise ValueError(f"{what}.value is an invalid regex: {exc}") from exc
    return _Matcher(kind, name, operator, value, regex)


def _parse_template(raw: object, index: int) -> _Template:
    what = f"templates[{index}]"
    obj = _require_fields(raw, _TEMPLATE_FIELDS, what)
    template_id = _non_empty_str(obj["id"], f"{what}.id")
    name = obj["name"]
    if not isinstance(name, str):
        raise ValueError(f"{what}.name must be a string")
    severity = obj["severity"]
    if severity not in SEVERITIES:
        raise ValueError(f"{what}.severity must be one of {SEVERITIES}")
    logic = obj["logic"]
    if logic not in LOGICS:
        raise ValueError(f"{what}.logic must be one of {LOGICS}")
    matchers = obj["matchers"]
    if not isinstance(matchers, list) or not matchers:
        raise ValueError(f"{what}.matchers must be a non-empty array")
    parsed = [
        _parse_matcher(item, f"{what}.matchers[{i}]")
        for i, item in enumerate(matchers)
    ]
    return _Template(template_id, name, severity, logic, parsed)


def _parse_observation(raw: object, index: int) -> _Observation:
    what = f"observations[{index}]"
    obj = _require_fields(raw, _OBSERVATION_FIELDS, what)
    observation_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    status = obj["status"]
    if not _is_int(status) or not 100 <= status <= 599:
        raise ValueError(f"{what}.status must be an integer between 100 and 599")
    headers = obj["headers"]
    if not isinstance(headers, dict):
        raise ValueError(f"{what}.headers must be an object")
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(f"{what}.headers must map strings to strings")
    body = obj["body"]
    if not isinstance(body, str):
        raise ValueError(f"{what}.body must be a string")
    return _Observation(observation_id, target, status, dict(headers), body)


def _apply_operator(matcher: _Matcher, text: str) -> bool:
    if matcher.operator == "equals":
        return text == matcher.value
    if matcher.operator == "contains":
        return matcher.value in text
    return matcher.regex.search(text) is not None


def _matcher_hit(matcher: _Matcher, observation: _Observation) -> bool:
    if matcher.kind == "status":
        return observation.status in matcher.value
    if matcher.kind == "header":
        wanted = matcher.name.lower()
        for key, value in observation.headers.items():
            if key.lower() == wanted:
                return _apply_operator(matcher, value)
        return False
    return _apply_operator(matcher, observation.body)


class Service:
    """Health, authorization-scope evaluation, and offline template matching."""

    name = "redforge"
    version = __version__

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def evaluate_scope(self, payload: object) -> dict[str, Any]:
        """Evaluate targets against allow/deny scope rules.

        Pure, local evaluation: no network access, no persistent state.
        Raises ValueError on any malformed input; never returns partial
        results.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        fields: dict[str, Any] = {}
        for key in ("allow", "deny", "targets"):
            if key not in payload:
                raise ValueError(f"missing field: {key}")
            fields[key] = payload[key]
        for key, value in fields.items():
            if not isinstance(value, list):
                raise ValueError(f"field {key} must be an array")
            if len(value) > MAX_RULES_PER_FIELD:
                raise ValueError(
                    f"field {key} exceeds {MAX_RULES_PER_FIELD} entries"
                )
        if not fields["targets"]:
            raise ValueError("targets must not be empty")

        allow_rules = [
            _parse_entry(raw, allow_wildcard=True) for raw in fields["allow"]
        ]
        deny_rules = [
            _parse_entry(raw, allow_wildcard=True) for raw in fields["deny"]
        ]
        decisions = [
            self._decide(raw, allow_rules, deny_rules)
            for raw in fields["targets"]
        ]
        return {"decisions": decisions}

    def _decide(
        self,
        raw_target: object,
        allow_rules: list[_Entry],
        deny_rules: list[_Entry],
    ) -> dict[str, Any]:
        target = _parse_entry(raw_target, allow_wildcard=False)
        allowed, reason, matched_rule = self._evaluate(
            target, allow_rules, deny_rules
        )
        return _decision(raw_target, target.text, allowed, reason, matched_rule)

    def _evaluate(
        self,
        target: _Entry,
        allow_rules: list[_Entry],
        deny_rules: list[_Entry],
    ) -> tuple[bool, str, str | None]:
        """Decide a parsed target; return (allowed, reason, matched_rule)."""
        if target.kind == "network":
            # A CIDR target needs full containment in an allow network and
            # must not intersect any deny network.
            for rule in deny_rules:
                if (
                    rule.kind == "network"
                    and rule.value.version == target.value.version
                    and target.value.overlaps(rule.value)
                ):
                    return False, "deny_overlap", rule.text
            for rule in allow_rules:
                if (
                    rule.kind == "network"
                    and rule.value.version == target.value.version
                    and target.value.subnet_of(rule.value)
                ):
                    return True, "allowed", rule.text
            return False, "no_allow_match", None
        # Deny wins over allow for point targets.
        for rule in deny_rules:
            if _matches(rule, target):
                return False, "deny_match", rule.text
        for rule in allow_rules:
            if _matches(rule, target):
                return True, "allowed", rule.text
        return False, "no_allow_match", None

    def match_vulnerabilities(self, payload: object) -> dict[str, Any]:
        """Match offline HTTP observations against vulnerability templates.

        Pure, local evaluation: no network access, no persistent state. All
        observation targets are checked against the allow/deny scope before
        any matching happens. Raises ValueError on malformed input and
        ScopeViolationError when any target is out of scope; never returns
        partial results.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "templates", "observations"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        for key in ("allow", "deny"):
            value = payload[key]
            if not isinstance(value, list):
                raise ValueError(f"field {key} must be an array")
            if len(value) > MAX_RULES_PER_FIELD:
                raise ValueError(
                    f"field {key} exceeds {MAX_RULES_PER_FIELD} entries"
                )
        allow_rules = [
            _parse_entry(raw, allow_wildcard=True) for raw in payload["allow"]
        ]
        deny_rules = [
            _parse_entry(raw, allow_wildcard=True) for raw in payload["deny"]
        ]

        for key in ("templates", "observations"):
            value = payload[key]
            if not isinstance(value, list) or not value:
                raise ValueError(f"field {key} must be a non-empty array")
        templates = [
            _parse_template(raw, i) for i, raw in enumerate(payload["templates"])
        ]
        observations = [
            _parse_observation(raw, i)
            for i, raw in enumerate(payload["observations"])
        ]
        self._require_unique_ids(
            (template.id for template in templates), "template"
        )
        self._require_unique_ids(
            (observation.id for observation in observations), "observation"
        )

        # Scope gate: every observation target must be authorized before any
        # matching happens; a single rejection voids the whole request.
        for observation in observations:
            allowed, reason, _ = self._evaluate(
                observation.target, allow_rules, deny_rules
            )
            if not allowed:
                raise ScopeViolationError(
                    f"target {observation.target.text} out of scope: {reason}"
                )

        findings: list[dict[str, Any]] = []
        for observation in observations:
            for template in templates:
                evidence = [
                    i
                    for i, matcher in enumerate(template.matchers)
                    if _matcher_hit(matcher, observation)
                ]
                if template.logic == "all":
                    hit = len(evidence) == len(template.matchers)
                else:
                    hit = bool(evidence)
                if hit:
                    findings.append(
                        {
                            "observation_id": observation.id,
                            "target": observation.target.text,
                            "template_id": template.id,
                            "name": template.name,
                            "severity": template.severity,
                            "evidence": evidence,
                        }
                    )
        return {"findings": findings}

    @staticmethod
    def _require_unique_ids(ids: Any, what: str) -> None:
        seen: set[str] = set()
        for item in ids:
            if item in seen:
                raise ValueError(f"duplicate {what} id: {item!r}")
            seen.add(item)
