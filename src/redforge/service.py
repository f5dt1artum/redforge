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

_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

SEVERITIES = ("info", "low", "medium", "high", "critical")
MATCH_OPERATORS = ("equals", "contains", "regex")
MATCHER_TYPES = ("status", "header", "body")


class ScopeViolation(ValueError):
    """At least one observation target is outside the authorized scope."""


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


def _require_object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    return value


def _require_fields(obj: dict[str, Any], fields: tuple[str, ...], what: str) -> None:
    for field in fields:
        if field not in obj:
            raise ValueError(f"{what} missing field: {field}")


def _reject_extra(obj: dict[str, Any], allowed: tuple[str, ...], what: str) -> None:
    extra = set(obj) - set(allowed)
    if extra:
        raise ValueError(f"{what} has undefined field(s): {sorted(extra)[0]}")


def _require_nonempty_str(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty string")
    return value


def _require_enum(value: object, choices: tuple[str, ...], what: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{what} must be one of {', '.join(choices)}")
    return value


def _unique_nonempty_ids(items: list[dict[str, Any]], what: str) -> None:
    seen: set[str] = set()
    for item in items:
        item_id = _require_nonempty_str(item.get("id"), f"{what} id")
        if item_id in seen:
            raise ValueError(f"duplicate {what} id: {item_id!r}")
        seen.add(item_id)


class Service:
    """Health reporting plus authorization-scope evaluation."""

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
        if target.kind == "network":
            # A CIDR target needs full containment in an allow network and
            # must not intersect any deny network.
            for rule in deny_rules:
                if (
                    rule.kind == "network"
                    and rule.value.version == target.value.version
                    and target.value.overlaps(rule.value)
                ):
                    return _decision(
                        raw_target, target.text, False, "deny_overlap", rule.text
                    )
            for rule in allow_rules:
                if (
                    rule.kind == "network"
                    and rule.value.version == target.value.version
                    and target.value.subnet_of(rule.value)
                ):
                    return _decision(
                        raw_target, target.text, True, "allowed", rule.text
                    )
            return _decision(
                raw_target, target.text, False, "no_allow_match", None
            )
        # Deny wins over allow for point targets.
        for rule in deny_rules:
            if _matches(rule, target):
                return _decision(
                    raw_target, target.text, False, "deny_match", rule.text
                )
        for rule in allow_rules:
            if _matches(rule, target):
                return _decision(raw_target, target.text, True, "allowed", rule.text)
        return _decision(raw_target, target.text, False, "no_allow_match", None)

    def match_vulnerabilities(self, payload: object) -> dict[str, Any]:
        """Match offline HTTP observations against vulnerability templates.

        Purely local: observations are already-collected evidence and no
        network access occurs. Every observation target must pass the same
        allow/deny scope rules as ``evaluate_scope``; a single rejected
        target aborts the whole request with ScopeViolation. Malformed
        input raises ValueError. No partial results are ever returned.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        _reject_extra(payload, ("allow", "deny", "templates", "observations"), "payload")
        _require_fields(
            payload, ("allow", "deny", "templates", "observations"), "payload"
        )
        for field in ("allow", "deny", "templates", "observations"):
            if not isinstance(payload[field], list):
                raise ValueError(f"field {field} must be an array")
        if len(payload["allow"]) > MAX_RULES_PER_FIELD:
            raise ValueError(
                f"field allow exceeds {MAX_RULES_PER_FIELD} entries"
            )
        if len(payload["deny"]) > MAX_RULES_PER_FIELD:
            raise ValueError(f"field deny exceeds {MAX_RULES_PER_FIELD} entries")
        if not payload["templates"]:
            raise ValueError("templates must not be empty")
        if not payload["observations"]:
            raise ValueError("observations must not be empty")

        # Parse and validate the whole request before any authorization or
        # matching decision, so malformed input never yields a scope result.
        observations = [
            self._parse_observation(raw) for raw in payload["observations"]
        ]
        _unique_nonempty_ids(observations, "observation")
        templates = [self._parse_template(raw) for raw in payload["templates"]]
        _unique_nonempty_ids(templates, "template")

        allow_rules = [
            _parse_entry(raw, allow_wildcard=True) for raw in payload["allow"]
        ]
        deny_rules = [
            _parse_entry(raw, allow_wildcard=True) for raw in payload["deny"]
        ]

        # Scope gate runs before any template work and covers every target.
        for observation in observations:
            decision = self._decide(
                observation["target"], allow_rules, deny_rules
            )
            if not decision["allowed"]:
                raise ScopeViolation(
                    f"target outside authorized scope: {observation['target']!r} "
                    f"({decision['reason']})"
                )

        findings: list[dict[str, Any]] = []
        for observation in observations:
            target = self._normalize_target(observation["target"])
            for template in templates:
                evidence = self._run_template(template, observation)
                if evidence is not None:
                    findings.append(
                        {
                            "observation_id": observation["id"],
                            "target": target,
                            "template_id": template["id"],
                            "name": template["name"],
                            "severity": template["severity"],
                            "evidence": evidence,
                        }
                    )
        return {"findings": findings}

    @staticmethod
    def _normalize_target(raw: str) -> str:
        return _parse_entry(raw, allow_wildcard=False).text

    @staticmethod
    def _parse_observation(raw: object) -> dict[str, Any]:
        obj = _require_object(raw, "observation")
        _reject_extra(obj, ("id", "target", "status", "headers", "body"), "observation")
        _require_fields(obj, ("id", "target", "status", "headers", "body"), "observation")
        obs_id = _require_nonempty_str(obj["id"], "observation id")
        _require_nonempty_str(obj["target"], "observation target")
        # Normalize eagerly so invalid targets raise invalid_request.
        Service._normalize_target(obj["target"])
        status = obj["status"]
        if not isinstance(status, int) or isinstance(status, bool) or not (
            100 <= status <= 599
        ):
            raise ValueError("observation status must be an integer in [100, 599]")
        headers = obj["headers"]
        if not isinstance(headers, dict):
            raise ValueError("observation headers must be an object")
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError("observation headers must map strings to strings")
        body = obj["body"]
        if not isinstance(body, str):
            raise ValueError("observation body must be a string")
        return {
            "id": obs_id,
            "target": obj["target"],
            "status": status,
            "headers": headers,
            "body": body,
        }

    @staticmethod
    def _parse_template(raw: object) -> dict[str, Any]:
        obj = _require_object(raw, "template")
        _reject_extra(obj, ("id", "name", "severity", "logic", "matchers"), "template")
        _require_fields(obj, ("id", "name", "severity", "logic", "matchers"), "template")
        template_id = _require_nonempty_str(obj["id"], "template id")
        name = obj["name"]
        if not isinstance(name, str):
            raise ValueError("template name must be a string")
        severity = _require_enum(obj["severity"], SEVERITIES, "template severity")
        logic = _require_enum(obj["logic"], ("all", "any"), "template logic")
        matchers_raw = obj["matchers"]
        if not isinstance(matchers_raw, list) or not matchers_raw:
            raise ValueError("template matchers must be a non-empty array")
        matchers = [
            Service._parse_matcher(item, index)
            for index, item in enumerate(matchers_raw)
        ]
        return {
            "id": template_id,
            "name": name,
            "severity": severity,
            "logic": logic,
            "matchers": matchers,
        }

    @staticmethod
    def _parse_matcher(raw: object, index: int) -> dict[str, Any]:
        what = f"matcher[{index}]"
        obj = _require_object(raw, what)
        kind = obj.get("type")
        if not isinstance(kind, str) or kind not in MATCHER_TYPES:
            raise ValueError(
                f"{what} type must be one of {', '.join(MATCHER_TYPES)}"
            )
        if kind == "status":
            _reject_extra(obj, ("type", "values"), what)
            values = obj.get("values")
            if (
                not isinstance(values, list)
                or not values
                or any(
                    not isinstance(v, int) or isinstance(v, bool) for v in values
                )
            ):
                raise ValueError(f"{what} values must be a non-empty integer array")
            return {"type": "status", "values": list(values)}
        if kind == "header":
            _reject_extra(obj, ("type", "name", "operator", "value"), what)
            name = obj.get("name")
            if not isinstance(name, str):
                raise ValueError(f"{what} name must be a string")
            operator = _require_enum(
                obj.get("operator"), MATCH_OPERATORS, f"{what} operator"
            )
            value = _require_nonempty_str(obj.get("value"), f"{what} value")
            pattern = Service._compile_pattern(operator, value, what)
            return {
                "type": "header",
                "name": name,
                "operator": operator,
                "value": value,
                "pattern": pattern,
            }
        _reject_extra(obj, ("type", "operator", "value"), what)
        operator = _require_enum(
            obj.get("operator"), MATCH_OPERATORS, f"{what} operator"
        )
        value = _require_nonempty_str(obj.get("value"), f"{what} value")
        pattern = Service._compile_pattern(operator, value, what)
        return {
            "type": "body",
            "operator": operator,
            "value": value,
            "pattern": pattern,
        }

    @staticmethod
    def _compile_pattern(operator: str, value: str, what: str):
        if operator != "regex":
            return None
        try:
            return re.compile(value, re.UNICODE)
        except re.error as exc:
            raise ValueError(f"{what} has an invalid regex: {exc}") from exc

    @staticmethod
    def _run_template(
        template: dict[str, Any], observation: dict[str, Any]
    ) -> list[int] | None:
        """Indices of matching matchers in original order, or None."""
        hits: list[int] = []
        for index, matcher in enumerate(template["matchers"]):
            if Service._match_matcher(matcher, observation):
                hits.append(index)
        if template["logic"] == "all":
            return hits if len(hits) == len(template["matchers"]) else None
        return hits if hits else None

    @staticmethod
    def _match_matcher(matcher: dict[str, Any], observation: dict[str, Any]) -> bool:
        kind = matcher["type"]
        if kind == "status":
            return observation["status"] in matcher["values"]
        if kind == "header":
            actual = Service._header_value(observation["headers"], matcher["name"])
            if actual is None:
                return False
            return Service._string_match(matcher, actual)
        return Service._string_match(matcher, observation["body"])

    @staticmethod
    def _header_value(headers: dict[str, str], name: str) -> str | None:
        wanted = name.lower()
        for header_name, value in headers.items():
            if header_name.lower() == wanted:
                return value
        return None

    @staticmethod
    def _string_match(matcher: dict[str, Any], actual: str) -> bool:
        operator = matcher["operator"]
        if operator == "equals":
            return actual == matcher["value"]
        if operator == "contains":
            return matcher["value"] in actual
        return matcher["pattern"].search(actual) is not None
