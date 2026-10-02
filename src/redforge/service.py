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
_FINDING_FIELDS = frozenset(
    {"observation_id", "target", "template_id", "name", "severity", "evidence"}
)
_RUN_FIELDS = frozenset({"id", "reliability", "findings"})
_CONSOLIDATED_FIELDS = frozenset(
    {
        "target",
        "template_id",
        "name",
        "severity",
        "observation_ids",
        "sources",
        "evidence",
        "confidence",
    }
)
_REQUIREMENT_FIELDS = frozenset({"template_id", "min_severity", "min_confidence"})
_STAGE_FIELDS = frozenset({"id", "name", "logic", "requires", "depends_on"})

_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

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


@dataclass(frozen=True)
class _Finding:
    """A validated finding produced by offline template matching."""

    observation_id: str
    target: _Entry
    template_id: str
    name: str
    severity: str
    evidence: tuple[int, ...]


def _parse_finding(raw: object, what: str) -> _Finding:
    obj = _require_fields(raw, _FINDING_FIELDS, what)
    observation_id = _non_empty_str(obj["observation_id"], f"{what}.observation_id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    template_id = _non_empty_str(obj["template_id"], f"{what}.template_id")
    name = obj["name"]
    if not isinstance(name, str) or not name:
        raise ValueError(f"{what}.name must be a non-empty string")
    severity = obj["severity"]
    if severity not in SEVERITIES:
        raise ValueError(f"{what}.severity must be one of {SEVERITIES}")
    evidence = obj["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError(f"{what}.evidence must be a non-empty array")
    for item in evidence:
        if not _is_int(item) or item < 0:
            raise ValueError(f"{what}.evidence must contain only non-negative integers")
    return _Finding(
        observation_id, target, template_id, name, severity, tuple(evidence)
    )


@dataclass(frozen=True)
class _ConsolidatedItem:
    """A validated item shaped like a consolidate response entry."""

    target: _Entry
    template_id: str
    name: str
    severity: str
    observation_ids: tuple[str, ...]
    sources: tuple[str, ...]
    evidence: tuple[int, ...]
    confidence: int


def _parse_consolidated_item(raw: object, what: str) -> _ConsolidatedItem:
    obj = _require_fields(raw, _CONSOLIDATED_FIELDS, what)
    target = _parse_entry(obj["target"], allow_wildcard=False)
    template_id = _non_empty_str(obj["template_id"], f"{what}.template_id")
    name = obj["name"]
    if not isinstance(name, str) or not name:
        raise ValueError(f"{what}.name must be a non-empty string")
    severity = obj["severity"]
    if severity not in SEVERITIES:
        raise ValueError(f"{what}.severity must be one of {SEVERITIES}")
    observation_ids = obj["observation_ids"]
    if not isinstance(observation_ids, list):
        raise ValueError(f"{what}.observation_ids must be an array")
    for item in observation_ids:
        _non_empty_str(item, f"{what}.observation_ids[]")
    sources = obj["sources"]
    if not isinstance(sources, list):
        raise ValueError(f"{what}.sources must be an array")
    for item in sources:
        _non_empty_str(item, f"{what}.sources[]")
    evidence = obj["evidence"]
    if not isinstance(evidence, list):
        raise ValueError(f"{what}.evidence must be an array")
    for item in evidence:
        if not _is_int(item) or item < 0:
            raise ValueError(
                f"{what}.evidence must contain only non-negative integers"
            )
    confidence = obj["confidence"]
    if not _is_int(confidence) or not 0 <= confidence <= 100:
        raise ValueError(
            f"{what}.confidence must be an integer between 0 and 100"
        )
    return _ConsolidatedItem(
        target,
        template_id,
        name,
        severity,
        tuple(observation_ids),
        tuple(sources),
        tuple(evidence),
        confidence,
    )


@dataclass(frozen=True)
class _Requirement:
    """A validated stage requirement against consolidated findings."""

    template_id: str
    min_severity: str
    min_confidence: int


@dataclass(frozen=True)
class _Stage:
    """A validated attack-chain stage definition."""

    id: str
    name: str
    logic: str
    requires: tuple[_Requirement, ...]
    depends_on: tuple[str, ...]


def _parse_requirement(raw: object, what: str) -> _Requirement:
    obj = _require_fields(raw, _REQUIREMENT_FIELDS, what)
    template_id = _non_empty_str(obj["template_id"], f"{what}.template_id")
    min_severity = obj["min_severity"]
    if min_severity not in SEVERITIES:
        raise ValueError(f"{what}.min_severity must be one of {SEVERITIES}")
    min_confidence = obj["min_confidence"]
    if not _is_int(min_confidence) or not 0 <= min_confidence <= 100:
        raise ValueError(
            f"{what}.min_confidence must be an integer between 0 and 100"
        )
    return _Requirement(template_id, min_severity, min_confidence)


def _parse_stage(raw: object, index: int, seen_ids: set[str]) -> _Stage:
    what = f"stages[{index}]"
    obj = _require_fields(raw, _STAGE_FIELDS, what)
    stage_id = _non_empty_str(obj["id"], f"{what}.id")
    if stage_id in seen_ids:
        raise ValueError(f"duplicate stage id: {stage_id!r}")
    seen_ids.add(stage_id)
    name = _non_empty_str(obj["name"], f"{what}.name")
    logic = obj["logic"]
    if logic not in LOGICS:
        raise ValueError(f"{what}.logic must be one of {LOGICS}")
    requires = obj["requires"]
    if not isinstance(requires, list) or not requires:
        raise ValueError(f"{what}.requires must be a non-empty array")
    parsed_requires = tuple(
        _parse_requirement(item, f"{what}.requires[{i}]")
        for i, item in enumerate(requires)
    )
    depends_on = obj["depends_on"]
    if not isinstance(depends_on, list):
        raise ValueError(f"{what}.depends_on must be an array")
    deps: list[str] = []
    seen_deps: set[str] = set()
    for dep in depends_on:
        if not isinstance(dep, str) or not dep:
            raise ValueError(
                f"{what}.depends_on must contain only non-empty strings"
            )
        if dep in seen_deps:
            raise ValueError(f"{what}.depends_on has duplicate entry: {dep!r}")
        seen_deps.add(dep)
        deps.append(dep)
    return _Stage(stage_id, name, logic, parsed_requires, tuple(deps))


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

    def consolidate_findings(self, payload: object) -> dict[str, Any]:
        """Consolidate matched findings collected across multiple scans.

        Pure, local evaluation: no network access, no persistent state. The
        allow/deny rules gate every finding target first (any unauthorized
        target raises ScopeViolationError); findings are then de-duplicated by
        normalized target and case-sensitive template_id. Raises ValueError
        on any malformed input; never returns partial results.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "runs"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)
        runs = self._parse_runs(payload["runs"])

        # Scope gate: every finding target must be authorized before any
        # consolidation happens; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (finding.target for _, _, findings in runs for finding in findings),
            allow_rules,
            deny_rules,
        )
        return {"consolidated": self._consolidate(runs)}

    @staticmethod
    def _parse_scope_rules(
        payload: dict[str, Any]
    ) -> tuple[list[_Entry], list[_Entry]]:
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
        return allow_rules, deny_rules

    @staticmethod
    def _parse_runs(raw_runs: object) -> list[tuple[str, int, list[_Finding]]]:
        if not isinstance(raw_runs, list) or not raw_runs:
            raise ValueError("field runs must be a non-empty array")

        runs: list[tuple[str, int, list[_Finding]]] = []
        seen_run_ids: set[str] = set()
        for i, raw_run in enumerate(raw_runs):
            run_what = f"runs[{i}]"
            obj = _require_fields(raw_run, _RUN_FIELDS, run_what)
            run_id = _non_empty_str(obj["id"], f"{run_what}.id")
            if run_id in seen_run_ids:
                raise ValueError(f"duplicate run id: {run_id!r}")
            seen_run_ids.add(run_id)
            reliability = obj["reliability"]
            if not _is_int(reliability) or not 0 <= reliability <= 100:
                raise ValueError(
                    f"{run_what}.reliability must be an integer between 0 and 100"
                )
            raw_findings = obj["findings"]
            if not isinstance(raw_findings, list):
                raise ValueError(f"{run_what}.findings must be an array")
            findings = [
                _parse_finding(raw, f"{run_what}.findings[{j}]")
                for j, raw in enumerate(raw_findings)
            ]
            runs.append((run_id, reliability, findings))
        return runs

    def _assert_targets_in_scope(
        self, targets: Any, allow_rules: list[_Entry], deny_rules: list[_Entry]
    ) -> None:
        """Scope gate: one unauthorized target voids the whole request."""
        for target in targets:
            allowed, reason, _ = self._evaluate(target, allow_rules, deny_rules)
            if not allowed:
                raise ScopeViolationError(
                    f"target {target.text} out of scope: {reason}"
                )

    @staticmethod
    def _consolidate(
        runs: list[tuple[str, int, list[_Finding]]],
    ) -> list[dict[str, Any]]:
        """De-duplicate validated findings by normalized target/template_id.

        Callers are responsible for authorizing every finding target first.
        """
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        order: list[tuple[str, str]] = []
        for _, _, findings in runs:
            for finding in findings:
                key = (finding.target.text, finding.template_id)
                group = groups.get(key)
                if group is None:
                    group = {
                        "name": finding.name,
                        "severity": finding.severity,
                        "observation_ids": [],
                        "_observation_seen": set(),
                        "sources": [],
                        "_source_seen": set(),
                        "evidence": set(),
                        "confidence": 0,
                    }
                    groups[key] = group
                    order.append(key)
                elif group["name"] != finding.name:
                    raise ValueError(
                        "conflicting names for "
                        f"({finding.target.text}, {finding.template_id}): "
                        f"{group['name']!r} vs {finding.name!r}"
                    )
                if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[
                    group["severity"]
                ]:
                    group["severity"] = finding.severity
                if finding.observation_id not in group["_observation_seen"]:
                    group["_observation_seen"].add(finding.observation_id)
                    group["observation_ids"].append(finding.observation_id)
                group["evidence"].update(finding.evidence)

        # Sources and confidence are attributed per distinct run, while
        # observation ids and evidence still count repeated in-run findings.
        for run_id, reliability, findings in runs:
            touched = {
                (finding.target.text, finding.template_id) for finding in findings
            }
            for key in touched:
                group = groups[key]
                if run_id not in group["_source_seen"]:
                    group["_source_seen"].add(run_id)
                    group["sources"].append(run_id)
                c = group["confidence"]
                group["confidence"] = c + (100 - c) * reliability // 100

        consolidated = []
        for key in order:
            group = groups[key]
            consolidated.append(
                {
                    "target": key[0],
                    "template_id": key[1],
                    "name": group["name"],
                    "severity": group["severity"],
                    "observation_ids": group["observation_ids"],
                    "sources": group["sources"],
                    "evidence": sorted(group["evidence"]),
                    "confidence": group["confidence"],
                }
            )
        return consolidated

    def retest_findings(self, payload: object) -> dict[str, Any]:
        """Compare one retest against a previous consolidation.

        Pure, local evaluation: no network access, no persistent state. The
        baseline carries the same shape as a consolidate response's
        ``consolidated`` array; retest_runs has the runs shape. All structure
        is validated and every target on both sides passes the scope gate
        before anything is compared. Raises ValueError on malformed input and
        ScopeViolationError for any out-of-scope target.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "baseline", "retest_runs"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)

        raw_baseline = payload["baseline"]
        if not isinstance(raw_baseline, list):
            raise ValueError("field baseline must be an array")
        baseline_items = [
            _parse_consolidated_item(raw, f"baseline[{i}]")
            for i, raw in enumerate(raw_baseline)
        ]

        runs = self._parse_runs(payload["retest_runs"])

        # Structural validation must finish before the scope gate, so a
        # duplicate baseline key is a 400 even when a target is out of scope.
        before: dict[tuple[str, str], dict[str, Any]] = {}
        for item in baseline_items:
            key = (item.target.text, item.template_id)
            if key in before:
                raise ValueError(
                    f"duplicate baseline key: ({key[0]!r}, {key[1]!r})"
                )
            before[key] = {
                "target": item.target.text,
                "template_id": item.template_id,
                "name": item.name,
                "severity": item.severity,
                "observation_ids": list(item.observation_ids),
                "sources": list(item.sources),
                "evidence": sorted(item.evidence),
                "confidence": item.confidence,
            }

        # Then gate every target from both sides; a single rejection voids
        # the comparison.
        self._assert_targets_in_scope(
            (item.target for item in baseline_items),
            allow_rules,
            deny_rules,
        )
        self._assert_targets_in_scope(
            (finding.target for _, _, findings in runs for finding in findings),
            allow_rules,
            deny_rules,
        )

        after_list = self._consolidate(runs)
        after = {
            (item["target"], item["template_id"]): item for item in after_list
        }

        comparisons: list[dict[str, Any]] = []
        persistent = resolved = new = 0
        # Baseline order first: same key is persistent, a missing key resolved.
        for item in baseline_items:
            key = (item.target.text, item.template_id)
            current = after.get(key)
            if current is None:
                status = "resolved"
                resolved += 1
            else:
                status = "persistent"
                persistent += 1
            comparisons.append(
                {
                    "target": key[0],
                    "template_id": key[1],
                    "name": item.name,
                    "status": status,
                    "before": before[key],
                    "after": current,
                }
            )
        # Keys absent from the baseline are new, in first-occurrence order.
        for item in after_list:
            key = (item["target"], item["template_id"])
            if key in before:
                continue
            new += 1
            comparisons.append(
                {
                    "target": key[0],
                    "template_id": key[1],
                    "name": item["name"],
                    "status": "new",
                    "before": None,
                    "after": item,
                }
            )

        return {
            "comparisons": comparisons,
            "summary": {
                "total_before": len(before),
                "total_after": len(after),
                "persistent": persistent,
                "resolved": resolved,
                "new": new,
            },
        }

    def plan_attack_chains(self, payload: object) -> dict[str, Any]:
        """Plan attack-chain stages against consolidated findings per target.

        Pure, local evaluation: no network access, no persistent state, no
        stage execution. The findings carry the same shape as a consolidate
        response's ``consolidated`` array and may be empty; stages form a
        dependency DAG evaluated in topological order. All structure is
        validated and every finding target passes the scope gate before any
        planning happens. Raises ValueError on malformed input and
        ScopeViolationError for any out-of-scope target; never returns
        partial plans.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "findings", "stages"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)

        raw_findings = payload["findings"]
        if not isinstance(raw_findings, list):
            raise ValueError("field findings must be an array")
        findings = [
            _parse_consolidated_item(raw, f"findings[{i}]")
            for i, raw in enumerate(raw_findings)
        ]

        raw_stages = payload["stages"]
        if not isinstance(raw_stages, list) or not raw_stages:
            raise ValueError("field stages must be a non-empty array")
        seen_ids: set[str] = set()
        stages = [
            _parse_stage(raw, i, seen_ids) for i, raw in enumerate(raw_stages)
        ]

        # Structural validation must finish before the scope gate, so a
        # duplicate finding key or a broken dependency graph is a 400 even
        # when a target is out of scope.
        seen_keys: set[tuple[str, str]] = set()
        for item in findings:
            key = (item.target.text, item.template_id)
            if key in seen_keys:
                raise ValueError(
                    f"duplicate finding key: ({key[0]!r}, {key[1]!r})"
                )
            seen_keys.add(key)
        ordered_stages = self._resolve_stage_order(stages)

        # Then gate every finding target; a single rejection voids the plan.
        self._assert_targets_in_scope(
            (item.target for item in findings), allow_rules, deny_rules
        )

        # Group findings by normalized target, keeping first-occurrence order.
        groups: dict[str, list[_ConsolidatedItem]] = {}
        for item in findings:
            groups.setdefault(item.target.text, []).append(item)

        plans = [
            {
                "target": target,
                "stages": self._evaluate_stages(ordered_stages, target_findings),
            }
            for target, target_findings in groups.items()
        ]
        return {"plans": plans}

    @staticmethod
    def _resolve_stage_order(stages: list[_Stage]) -> list[_Stage]:
        """Topologically order stages; same level keeps input order.

        Raises ValueError on self-references, unknown ids, or cycles.
        """
        known = {stage.id for stage in stages}
        for stage in stages:
            for dep in stage.depends_on:
                if dep == stage.id:
                    raise ValueError(f"stage {stage.id!r} depends on itself")
                if dep not in known:
                    raise ValueError(
                        f"stage {stage.id!r} depends on unknown id: {dep!r}"
                    )
        remaining = list(stages)
        done: set[str] = set()
        ordered: list[_Stage] = []
        while remaining:
            ready_now = [
                stage
                for stage in remaining
                if all(dep in done for dep in stage.depends_on)
            ]
            if not ready_now:
                raise ValueError("stage dependencies form a cycle")
            for stage in ready_now:
                done.add(stage.id)
            ordered.extend(ready_now)
            remaining = [stage for stage in remaining if stage.id not in done]
        return ordered

    @staticmethod
    def _evaluate_stages(
        ordered_stages: list[_Stage], findings: list[_ConsolidatedItem]
    ) -> list[dict[str, Any]]:
        """Evaluate stages in topological order against one target's findings."""
        statuses: dict[str, str] = {}
        results: list[dict[str, Any]] = []
        for stage in ordered_stages:
            hits = [
                any(
                    item.template_id == req.template_id
                    and _SEVERITY_RANK[item.severity]
                    >= _SEVERITY_RANK[req.min_severity]
                    and item.confidence >= req.min_confidence
                    for item in findings
                )
                for req in stage.requires
            ]
            condition_met = all(hits) if stage.logic == "all" else any(hits)
            if not condition_met:
                status, reason = "skipped", "missing_requirements"
            elif all(statuses[dep] == "ready" for dep in stage.depends_on):
                status, reason = "ready", None
            else:
                status, reason = "skipped", "dependency_blocked"
            statuses[stage.id] = status
            results.append(
                {
                    "id": stage.id,
                    "name": stage.name,
                    "status": status,
                    "reason": reason,
                }
            )
        return results

    @staticmethod
    def _require_unique_ids(ids: Any, what: str) -> None:
        seen: set[str] = set()
        for item in ids:
            if item in seen:
                raise ValueError(f"duplicate {what} id: {item!r}")
            seen.add(item)
