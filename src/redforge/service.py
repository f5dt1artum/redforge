"""Core service surface for RedForge.

The frozen baseline only reports process health. Later work adds the real
capabilities described in README.md behind this module; keep the public
surface here backward compatible.
"""

from __future__ import annotations

import base64
import heapq
import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from . import __version__

MAX_RULES_PER_FIELD = 1000

SEVERITIES = ("info", "low", "medium", "high", "critical")
LOGICS = ("all", "any")
OPERATORS = ("equals", "contains", "regex")

# Weakness codes are ordered by the fixed evaluation order; their severities
# are combined by taking the highest rank per finding.
_CREDENTIAL_SEVERITY = {
    "empty_secret": "critical",
    "username_equals_secret": "critical",
    "dictionary_secret": "high",
    "short_secret": "medium",
}

_OBSERVATION_FIELDS = frozenset({"id", "target", "status", "headers", "body"})
_PORT_OBSERVATION_FIELDS = frozenset(
    {"id", "target", "port", "transport", "banner"}
)
_FINGERPRINT_FIELDS = frozenset(
    {"id", "name", "service", "priority", "logic", "matchers"}
)
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
_COMPARISON_FIELDS = frozenset(
    {"target", "template_id", "name", "status", "before", "after"}
)
_PLAN_FIELDS = frozenset({"target", "stages"})
_STAGE_RESULT_FIELDS = frozenset({"id", "name", "status", "reason"})
_POLICY_FIELDS = frozenset({"min_length", "weak_secrets"})
_CREDENTIAL_ATTEMPT_FIELDS = frozenset(
    {
        "id",
        "target",
        "port",
        "transport",
        "service",
        "username",
        "secret",
        "authenticated",
    }
)
_PAYLOAD_ITEM_FIELDS = frozenset({"id", "template", "variables", "variants"})
_PAYLOAD_VARIANT_FIELDS = frozenset({"id", "steps"})
_SESSION_FIELDS = frozenset({"id", "target", "privilege"})
_TRANSITION_FIELDS = frozenset({"id", "from", "to", "technique", "cost"})
_GOAL_FIELDS = frozenset({"id", "target", "min_privilege"})

PRIVILEGES = ("user", "admin", "system")
_PRIVILEGE_RANK = {name: index for index, name in enumerate(PRIVILEGES)}

PAYLOAD_STEPS = ("url_percent", "base64", "hex")
# Percent-encoding leaves the RFC 3986 unreserved set untouched.
_PERCENT_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_VARIABLE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

COMPARISON_STATUSES = ("persistent", "resolved", "new")
_STAGE_RESULT_COMBOS = frozenset(
    {
        ("ready", None),
        ("skipped", "missing_requirements"),
        ("skipped", "dependency_blocked"),
    }
)

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
class _PortObservation:
    """A validated port observation.

    target is the parsed scope entry; its text attribute is the normalized
    form reported back in assets.
    """

    id: str
    target: _Entry
    port: int
    transport: str
    banner: str


@dataclass(frozen=True)
class _PortMatcher:
    """A validated service-fingerprint matcher.

    kind is one of "ports", "transport", "banner". For ports matchers value
    is a tuple of distinct valid ports in input order; for transport matchers
    value is "tcp" or "udp"; for banner matchers value is the non-empty
    comparison string and regex holds the compiled pattern for "regex".
    """

    kind: str
    operator: str | None
    value: Any
    regex: Any = None


@dataclass(frozen=True)
class _Fingerprint:
    id: str
    name: str
    service: str
    priority: int
    logic: str
    matchers: tuple[_PortMatcher, ...]


def _parse_port_matcher(raw: object, what: str) -> _PortMatcher:
    if not isinstance(raw, dict):
        raise ValueError(f"{what} must be an object")
    keys = set(raw)
    if keys == {"ports"}:
        ports = raw["ports"]
        if not isinstance(ports, list) or not ports:
            raise ValueError(f"{what}.ports must be a non-empty array")
        seen: set[int] = set()
        parsed_ports: list[int] = []
        for item in ports:
            if not _is_int(item) or not 1 <= item <= 65535:
                raise ValueError(
                    f"{what}.ports must contain only integers between 1 and 65535"
                )
            if item in seen:
                raise ValueError(f"{what}.ports has duplicate port: {item}")
            seen.add(item)
            parsed_ports.append(item)
        return _PortMatcher("ports", None, tuple(parsed_ports))
    if keys == {"transport"}:
        transport = raw["transport"]
        if transport not in ("tcp", "udp"):
            raise ValueError(f"{what}.transport must be 'tcp' or 'udp'")
        return _PortMatcher("transport", None, transport)
    if keys == {"operator", "value"}:
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
        return _PortMatcher("banner", operator, value, regex)
    raise ValueError(f"{what} has unknown or missing fields")


def _parse_fingerprint(raw: object, index: int) -> _Fingerprint:
    what = f"fingerprints[{index}]"
    obj = _require_fields(raw, _FINGERPRINT_FIELDS, what)
    fingerprint_id = _non_empty_str(obj["id"], f"{what}.id")
    name = _non_empty_str(obj["name"], f"{what}.name")
    service = _non_empty_str(obj["service"], f"{what}.service")
    priority = obj["priority"]
    if not _is_int(priority):
        raise ValueError(f"{what}.priority must be an integer")
    logic = obj["logic"]
    if logic not in LOGICS:
        raise ValueError(f"{what}.logic must be one of {LOGICS}")
    matchers = obj["matchers"]
    if not isinstance(matchers, list) or not matchers:
        raise ValueError(f"{what}.matchers must be a non-empty array")
    parsed_matchers = tuple(
        _parse_port_matcher(item, f"{what}.matchers[{i}]")
        for i, item in enumerate(matchers)
    )
    return _Fingerprint(
        fingerprint_id, name, service, priority, logic, parsed_matchers
    )


def _parse_port_observation(raw: object, index: int) -> _PortObservation:
    what = f"observations[{index}]"
    obj = _require_fields(raw, _PORT_OBSERVATION_FIELDS, what)
    observation_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    port = obj["port"]
    if not _is_int(port) or not 1 <= port <= 65535:
        raise ValueError(f"{what}.port must be an integer between 1 and 65535")
    transport = obj["transport"]
    if transport not in ("tcp", "udp"):
        raise ValueError(f"{what}.transport must be 'tcp' or 'udp'")
    banner = obj["banner"]
    if not isinstance(banner, str):
        raise ValueError(f"{what}.banner must be a string")
    return _PortObservation(observation_id, target, port, transport, banner)


@dataclass(frozen=True)
class _CredentialPolicy:
    """A validated credential-analysis policy."""

    min_length: int
    weak_secrets: tuple[str, ...]


@dataclass(frozen=True)
class _CredentialAttempt:
    """A validated credential observation.

    target is the parsed scope entry; its text attribute is the normalized
    form reported back in findings.
    """

    id: str
    target: _Entry
    port: int
    transport: str
    service: str
    username: str
    secret: str
    authenticated: bool


def _parse_credential_policy(raw: object) -> _CredentialPolicy:
    obj = _require_fields(raw, _POLICY_FIELDS, "policy")
    min_length = obj["min_length"]
    if not _is_int(min_length) or not 1 <= min_length <= 128:
        raise ValueError("policy.min_length must be an integer between 1 and 128")
    raw_secrets = obj["weak_secrets"]
    if not isinstance(raw_secrets, list):
        raise ValueError("policy.weak_secrets must be an array")
    secrets: list[str] = []
    seen: set[str] = set()
    for item in raw_secrets:
        if not isinstance(item, str) or not item:
            raise ValueError(
                "policy.weak_secrets must contain only non-empty strings"
            )
        if item in seen:
            raise ValueError("policy.weak_secrets has duplicate entry")
        seen.add(item)
        secrets.append(item)
    return _CredentialPolicy(min_length, tuple(secrets))


def _parse_credential_attempt(raw: object, index: int) -> _CredentialAttempt:
    what = f"attempts[{index}]"
    obj = _require_fields(raw, _CREDENTIAL_ATTEMPT_FIELDS, what)
    attempt_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    port = obj["port"]
    if not _is_int(port) or not 1 <= port <= 65535:
        raise ValueError(f"{what}.port must be an integer between 1 and 65535")
    transport = obj["transport"]
    if transport not in ("tcp", "udp"):
        raise ValueError(f"{what}.transport must be 'tcp' or 'udp'")
    service = _non_empty_str(obj["service"], f"{what}.service")
    username = _non_empty_str(obj["username"], f"{what}.username")
    secret = obj["secret"]
    if not isinstance(secret, str):
        raise ValueError(f"{what}.secret must be a string")
    authenticated = obj["authenticated"]
    if not isinstance(authenticated, bool):
        raise ValueError(f"{what}.authenticated must be a boolean")
    return _CredentialAttempt(
        attempt_id,
        target,
        port,
        transport,
        service,
        username,
        secret,
        authenticated,
    )


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
class _Comparison:
    """A validated item shaped like a retest response comparison entry."""

    target: _Entry
    template_id: str
    name: str
    status: str
    before: _ConsolidatedItem | None
    after: _ConsolidatedItem | None


def _parse_comparison(raw: object, what: str) -> _Comparison:
    obj = _require_fields(raw, _COMPARISON_FIELDS, what)
    target = _parse_entry(obj["target"], allow_wildcard=False)
    template_id = _non_empty_str(obj["template_id"], f"{what}.template_id")
    name = obj["name"]
    if not isinstance(name, str) or not name:
        raise ValueError(f"{what}.name must be a non-empty string")
    status = obj["status"]
    if status not in COMPARISON_STATUSES:
        raise ValueError(f"{what}.status must be one of {COMPARISON_STATUSES}")
    before = obj["before"]
    after = obj["after"]
    if status == "persistent":
        if before is None or after is None:
            raise ValueError(
                f"{what} with status 'persistent' needs non-null before and after"
            )
    elif status == "resolved":
        if before is None or after is not None:
            raise ValueError(
                f"{what} with status 'resolved' needs before and null after"
            )
    elif before is not None or after is None:
        raise ValueError(
            f"{what} with status 'new' needs null before and non-null after"
        )
    parsed_before = (
        None
        if before is None
        else _parse_consolidated_item(before, f"{what}.before")
    )
    parsed_after = (
        None if after is None else _parse_consolidated_item(after, f"{what}.after")
    )
    key = (target.text, template_id)
    for side, item in (("before", parsed_before), ("after", parsed_after)):
        if item is not None and (item.target.text, item.template_id) != key:
            raise ValueError(
                f"{what}.{side} key does not match the comparison key"
            )
    return _Comparison(target, template_id, name, status, parsed_before, parsed_after)


@dataclass(frozen=True)
class _StageResult:
    """A validated item shaped like a plan response stage entry."""

    id: str
    name: str
    status: str
    reason: str | None


@dataclass(frozen=True)
class _Plan:
    """A validated item shaped like a plan response entry."""

    target: _Entry
    stages: tuple[_StageResult, ...]


def _parse_stage_result(raw: object, what: str) -> _StageResult:
    obj = _require_fields(raw, _STAGE_RESULT_FIELDS, what)
    stage_id = _non_empty_str(obj["id"], f"{what}.id")
    name = _non_empty_str(obj["name"], f"{what}.name")
    status = obj["status"]
    reason = obj["reason"]
    if not isinstance(status, str) or (status, reason) not in _STAGE_RESULT_COMBOS:
        raise ValueError(
            f"{what} has an unknown status/reason combination: "
            f"{status!r}/{reason!r}"
        )
    return _StageResult(stage_id, name, status, reason)


def _parse_plan(raw: object, index: int) -> _Plan:
    what = f"plans[{index}]"
    obj = _require_fields(raw, _PLAN_FIELDS, what)
    target = _parse_entry(obj["target"], allow_wildcard=False)
    stages = obj["stages"]
    if not isinstance(stages, list):
        raise ValueError(f"{what}.stages must be an array")
    seen_ids: set[str] = set()
    parsed: list[_StageResult] = []
    for i, raw_stage in enumerate(stages):
        stage = _parse_stage_result(raw_stage, f"{what}.stages[{i}]")
        if stage.id in seen_ids:
            raise ValueError(f"{what} has duplicate stage id: {stage.id!r}")
        seen_ids.add(stage.id)
        parsed.append(stage)
    return _Plan(target, tuple(parsed))


def _consolidated_dict(item: _ConsolidatedItem) -> dict[str, Any]:
    return {
        "target": item.target.text,
        "template_id": item.template_id,
        "name": item.name,
        "severity": item.severity,
        "observation_ids": list(item.observation_ids),
        "sources": list(item.sources),
        "evidence": list(item.evidence),
        "confidence": item.confidence,
    }


def _comparison_dict(comparison: _Comparison) -> dict[str, Any]:
    return {
        "target": comparison.target.text,
        "template_id": comparison.template_id,
        "name": comparison.name,
        "status": comparison.status,
        "before": (
            None
            if comparison.before is None
            else _consolidated_dict(comparison.before)
        ),
        "after": (
            None
            if comparison.after is None
            else _consolidated_dict(comparison.after)
        ),
    }


def _stage_result_dict(stage: _StageResult) -> dict[str, Any]:
    return {
        "id": stage.id,
        "name": stage.name,
        "status": stage.status,
        "reason": stage.reason,
    }


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


def _port_matcher_hit(matcher: _PortMatcher, observation: _PortObservation) -> bool:
    if matcher.kind == "ports":
        return observation.port in matcher.value
    if matcher.kind == "transport":
        return observation.transport == matcher.value
    return _apply_operator(matcher, observation.banner)


@dataclass(frozen=True)
class _PayloadVariant:
    """A validated payload variant: an ordered chain of encoding steps."""

    id: str
    steps: tuple[str, ...]


@dataclass(frozen=True)
class _PayloadItem:
    """A validated payload item with its template already rendered."""

    id: str
    rendered: str
    variants: tuple[_PayloadVariant, ...]


def _render_payload_template(template: str, variables: dict[str, str], what: str) -> str:
    """Substitute ${name} placeholders exactly once.

    Variable values are inserted verbatim and never re-scanned, so a value
    containing placeholders is not expanded. A missing reference, an unused
    variable, or a malformed placeholder makes the request invalid.
    """
    parts: list[str] = []
    referenced: set[str] = set()
    index = 0
    length = len(template)
    while index < length:
        if template[index] == "$" and index + 1 < length and template[index + 1] == "{":
            end = template.find("}", index + 2)
            if end == -1:
                raise ValueError(f"{what}.template has a malformed placeholder")
            name = template[index + 2 : end]
            if not _VARIABLE_NAME_RE.fullmatch(name) or name not in variables:
                raise ValueError(
                    f"{what}.template has a malformed or unresolved placeholder"
                )
            parts.append(variables[name])
            referenced.add(name)
            index = end + 1
        else:
            parts.append(template[index])
            index += 1
    unused = set(variables) - referenced
    if unused:
        raise ValueError(f"{what}.variables has unused variable: {sorted(unused)[0]!r}")
    return "".join(parts)


def _parse_payload_variant(raw: object, what: str) -> _PayloadVariant:
    obj = _require_fields(raw, _PAYLOAD_VARIANT_FIELDS, what)
    variant_id = _non_empty_str(obj["id"], f"{what}.id")
    raw_steps = obj["steps"]
    if not isinstance(raw_steps, list):
        raise ValueError(f"{what}.steps must be an array")
    steps: list[str] = []
    for step in raw_steps:
        if step not in PAYLOAD_STEPS:
            raise ValueError(f"{what}.steps has an unknown step: {step!r}")
        steps.append(step)
    return _PayloadVariant(variant_id, tuple(steps))


def _parse_payload_item(raw: object, index: int) -> _PayloadItem:
    what = f"items[{index}]"
    obj = _require_fields(raw, _PAYLOAD_ITEM_FIELDS, what)
    item_id = _non_empty_str(obj["id"], f"{what}.id")
    template = _non_empty_str(obj["template"], f"{what}.template")
    raw_variables = obj["variables"]
    if not isinstance(raw_variables, dict):
        raise ValueError(f"{what}.variables must be an object")
    variables: dict[str, str] = {}
    for name, value in raw_variables.items():
        if not isinstance(name, str) or not _VARIABLE_NAME_RE.fullmatch(name):
            raise ValueError(f"{what}.variables has invalid variable name: {name!r}")
        if not isinstance(value, str):
            raise ValueError(f"{what}.variables must map names to strings")
        variables[name] = value
    raw_variants = obj["variants"]
    if not isinstance(raw_variants, list):
        raise ValueError(f"{what}.variants must be an array")
    variants = [
        _parse_payload_variant(raw_variant, f"{what}.variants[{i}]")
        for i, raw_variant in enumerate(raw_variants)
    ]
    seen_variant_ids: set[str] = set()
    for variant in variants:
        if variant.id in seen_variant_ids:
            raise ValueError(f"{what} has duplicate variant id: {variant.id!r}")
        seen_variant_ids.add(variant.id)
    rendered = _render_payload_template(template, variables, what)
    return _PayloadItem(item_id, rendered, tuple(variants))


@dataclass(frozen=True)
class _EscalationSession:
    """A validated privilege-escalation session node."""

    id: str
    target: _Entry
    privilege: str


@dataclass(frozen=True)
class _EscalationTransition:
    """A validated directed, weighted edge between sessions."""

    id: str
    source: str
    destination: str
    technique: str
    cost: int


@dataclass(frozen=True)
class _EscalationGoal:
    """A validated privilege goal: a target at least at min_privilege."""

    id: str
    target: _Entry
    min_privilege: str


def _parse_escalation_session(raw: object, index: int) -> _EscalationSession:
    what = f"sessions[{index}]"
    obj = _require_fields(raw, _SESSION_FIELDS, what)
    session_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    privilege = obj["privilege"]
    if privilege not in PRIVILEGES:
        raise ValueError(f"{what}.privilege must be one of {PRIVILEGES}")
    return _EscalationSession(session_id, target, privilege)


def _parse_escalation_transition(raw: object, index: int) -> _EscalationTransition:
    what = f"transitions[{index}]"
    obj = _require_fields(raw, _TRANSITION_FIELDS, what)
    transition_id = _non_empty_str(obj["id"], f"{what}.id")
    source = _non_empty_str(obj["from"], f"{what}.from")
    destination = _non_empty_str(obj["to"], f"{what}.to")
    if source == destination:
        raise ValueError(f"{what} must not reference the same session in from and to")
    technique = _non_empty_str(obj["technique"], f"{what}.technique")
    cost = obj["cost"]
    if not _is_int(cost) or not 1 <= cost <= 100:
        raise ValueError(f"{what}.cost must be an integer between 1 and 100")
    return _EscalationTransition(
        transition_id, source, destination, technique, cost
    )


def _parse_escalation_goal(raw: object, index: int) -> _EscalationGoal:
    what = f"goals[{index}]"
    obj = _require_fields(raw, _GOAL_FIELDS, what)
    goal_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    min_privilege = obj["min_privilege"]
    if min_privilege not in PRIVILEGES:
        raise ValueError(f"{what}.min_privilege must be one of {PRIVILEGES}")
    return _EscalationGoal(goal_id, target, min_privilege)


def _url_percent_encode(text: str) -> str:
    """Percent-encode UTF-8 bytes, keeping the RFC 3986 unreserved set."""
    pieces: list[str] = []
    for char in text:
        if char in _PERCENT_SAFE:
            pieces.append(char)
        else:
            pieces.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
    return "".join(pieces)


def _base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _hex_encode(text: str) -> str:
    return "".join(f"{byte:02x}" for byte in text.encode("utf-8"))


_PAYLOAD_TRANSFORMS = {
    "url_percent": _url_percent_encode,
    "base64": _base64_encode,
    "hex": _hex_encode,
}


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

    def fingerprint_assets(self, payload: object) -> dict[str, Any]:
        """Identify local port observations as service assets.

        Pure, local evaluation: no network access, no persistent state. All
        structure is validated first (including duplicate ids and duplicate
        endpoints sharing normalized target, transport, and port); only then
        are observation targets checked against the allow/deny scope. Raises
        ValueError on malformed input and ScopeViolationError when any target
        is out of scope; never returns partial results.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "fingerprints", "observations"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)

        raw_fingerprints = payload["fingerprints"]
        if not isinstance(raw_fingerprints, list):
            raise ValueError("field fingerprints must be an array")
        fingerprints = [
            _parse_fingerprint(raw, i) for i, raw in enumerate(raw_fingerprints)
        ]
        self._require_unique_ids(
            (fingerprint.id for fingerprint in fingerprints), "fingerprint"
        )

        raw_observations = payload["observations"]
        if not isinstance(raw_observations, list):
            raise ValueError("field observations must be an array")
        observations = [
            _parse_port_observation(raw, i)
            for i, raw in enumerate(raw_observations)
        ]
        self._require_unique_ids(
            (observation.id for observation in observations), "observation"
        )
        # An endpoint is identified by normalized target, transport, port.
        seen_endpoints: set[tuple[str, str, int]] = set()
        for observation in observations:
            endpoint = (
                observation.target.text,
                observation.transport,
                observation.port,
            )
            if endpoint in seen_endpoints:
                raise ValueError(
                    "duplicate endpoint: "
                    f"({endpoint[0]!r}, {endpoint[1]}, {endpoint[2]})"
                )
            seen_endpoints.add(endpoint)

        # Scope gate: every observation target must be authorized before any
        # fingerprinting happens; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (observation.target for observation in observations),
            allow_rules,
            deny_rules,
        )

        groups: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for observation in observations:
            target = observation.target.text
            if target not in groups:
                groups[target] = []
                order.append(target)
            groups[target].append(self._identify_service(observation, fingerprints))

        assets = [
            {"target": target, "services": groups[target]} for target in order
        ]
        return {"assets": assets}

    @staticmethod
    def _identify_service(
        observation: _PortObservation, fingerprints: list[_Fingerprint]
    ) -> dict[str, Any]:
        """Pick the highest-priority matching fingerprint for one endpoint."""
        best: _Fingerprint | None = None
        best_evidence: list[int] = []
        # Input order decides priority ties, so only replace on a strict win.
        for fingerprint in fingerprints:
            evidence = [
                index
                for index, matcher in enumerate(fingerprint.matchers)
                if _port_matcher_hit(matcher, observation)
            ]
            if fingerprint.logic == "all":
                hit = len(evidence) == len(fingerprint.matchers)
            else:
                hit = bool(evidence)
            if hit and (best is None or fingerprint.priority > best.priority):
                best = fingerprint
                best_evidence = evidence
        service: dict[str, Any] = {
            "observation_id": observation.id,
            "port": observation.port,
            "transport": observation.transport,
        }
        if best is None:
            service.update(
                {
                    "service": "unknown",
                    "fingerprint_id": None,
                    "name": None,
                    "evidence": [],
                }
            )
        else:
            service.update(
                {
                    "service": best.service,
                    "fingerprint_id": best.id,
                    "name": best.name,
                    "evidence": best_evidence,
                }
            )
        return service

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

    def export_report(self, payload: object) -> dict[str, Any]:
        """Export existing results as one stable, local evidence report.

        Pure, local evaluation: no network access, no persistent state. The
        findings, comparisons, and plans carry the same shapes as the
        consolidate, retest, and attack-chains/plan response items. All
        structure and cross-consistency is validated first (any violation
        raises ValueError), then every target passes the scope gate (any
        rejection raises ScopeViolationError); never returns a partial
        report. The same input always produces the same report.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "title", "findings", "comparisons", "plans"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)

        title = payload["title"]
        if not isinstance(title, str) or not title:
            raise ValueError("field title must be a non-empty string")

        raw_findings = payload["findings"]
        if not isinstance(raw_findings, list):
            raise ValueError("field findings must be an array")
        findings = [
            _parse_consolidated_item(raw, f"findings[{i}]")
            for i, raw in enumerate(raw_findings)
        ]

        raw_comparisons = payload["comparisons"]
        if not isinstance(raw_comparisons, list):
            raise ValueError("field comparisons must be an array")
        comparisons = [
            _parse_comparison(raw, f"comparisons[{i}]")
            for i, raw in enumerate(raw_comparisons)
        ]

        raw_plans = payload["plans"]
        if not isinstance(raw_plans, list):
            raise ValueError("field plans must be an array")
        plans = [_parse_plan(raw, i) for i, raw in enumerate(raw_plans)]

        # Structural and cross-consistency validation must finish before the
        # scope gate, so an inconsistent report is a 400 even when a target
        # is out of scope.
        self._check_report_consistency(findings, comparisons, plans)

        # Then gate every target; a single rejection voids the whole report.
        self._assert_targets_in_scope(
            (item.target for item in findings), allow_rules, deny_rules
        )
        self._assert_targets_in_scope(
            (item.target for item in comparisons), allow_rules, deny_rules
        )
        self._assert_targets_in_scope(
            (plan.target for plan in plans), allow_rules, deny_rules
        )

        return {"report": self._build_report(title, findings, comparisons, plans)}

    @staticmethod
    def _check_report_consistency(
        findings: list[_ConsolidatedItem],
        comparisons: list[_Comparison],
        plans: list[_Plan],
    ) -> None:
        """Cross-validate keys and names across the three result arrays."""
        names: dict[tuple[str, str], str] = {}

        def register_name(key: tuple[str, str], name: str) -> None:
            known = names.get(key)
            if known is None:
                names[key] = name
            elif known != name:
                raise ValueError(
                    f"conflicting names for ({key[0]!r}, {key[1]!r}): "
                    f"{known!r} vs {name!r}"
                )

        finding_by_key: dict[tuple[str, str], _ConsolidatedItem] = {}
        for item in findings:
            key = (item.target.text, item.template_id)
            if key in finding_by_key:
                raise ValueError(
                    f"duplicate finding key: ({key[0]!r}, {key[1]!r})"
                )
            finding_by_key[key] = item
            register_name(key, item.name)

        comparison_keys: set[tuple[str, str]] = set()
        after_keys: set[tuple[str, str]] = set()
        for comparison in comparisons:
            key = (comparison.target.text, comparison.template_id)
            if key in comparison_keys:
                raise ValueError(
                    f"duplicate comparison key: ({key[0]!r}, {key[1]!r})"
                )
            comparison_keys.add(key)
            register_name(key, comparison.name)
            if comparison.before is not None:
                register_name(key, comparison.before.name)
            if comparison.after is not None:
                after_keys.add(key)
                register_name(key, comparison.after.name)

        if comparisons:
            # A non-null after must be the exact current finding for its
            # key, and every current finding must be compared.
            for comparison in comparisons:
                if comparison.after is None:
                    continue
                key = (comparison.target.text, comparison.template_id)
                current = finding_by_key.get(key)
                if current is None or current != comparison.after:
                    raise ValueError(
                        "comparison after does not match the current finding "
                        f"for key ({key[0]!r}, {key[1]!r})"
                    )
            for key in finding_by_key:
                if key not in after_keys:
                    raise ValueError(
                        "current finding not covered by comparisons: "
                        f"({key[0]!r}, {key[1]!r})"
                    )

        finding_targets = {item.target.text for item in findings}
        plan_targets: set[str] = set()
        for plan in plans:
            target = plan.target.text
            if target in plan_targets:
                raise ValueError(f"duplicate plan target: {target!r}")
            plan_targets.add(target)
            if target not in finding_targets:
                raise ValueError(
                    f"plan target has no current findings: {target!r}"
                )

    @staticmethod
    def _build_report(
        title: str,
        findings: list[_ConsolidatedItem],
        comparisons: list[_Comparison],
        plans: list[_Plan],
    ) -> dict[str, Any]:
        """Group validated results per normalized target and count them."""
        order: list[str] = []
        findings_by_target: dict[str, list[_ConsolidatedItem]] = {}
        for item in findings:
            target = item.target.text
            if target not in findings_by_target:
                findings_by_target[target] = []
                order.append(target)
            findings_by_target[target].append(item)
        comparisons_by_target: dict[str, list[_Comparison]] = {}
        for comparison in comparisons:
            target = comparison.target.text
            if target not in comparisons_by_target:
                comparisons_by_target[target] = []
                if target not in findings_by_target:
                    order.append(target)
            comparisons_by_target[target].append(comparison)
        plans_by_target = {plan.target.text: plan for plan in plans}

        targets = []
        for target in order:
            plan = plans_by_target.get(target)
            targets.append(
                {
                    "target": target,
                    "findings": [
                        _consolidated_dict(item)
                        for item in findings_by_target.get(target, [])
                    ],
                    "comparisons": [
                        _comparison_dict(comparison)
                        for comparison in comparisons_by_target.get(target, [])
                    ],
                    "stages": [
                        _stage_result_dict(stage)
                        for stage in (plan.stages if plan is not None else ())
                    ],
                }
            )

        summary = {
            "targets": len(targets),
            "current_findings": len(findings),
            "persistent": sum(
                1 for item in comparisons if item.status == "persistent"
            ),
            "resolved": sum(
                1 for item in comparisons if item.status == "resolved"
            ),
            "new": sum(1 for item in comparisons if item.status == "new"),
            "ready_stages": sum(
                1
                for plan in plans
                for stage in plan.stages
                if stage.status == "ready"
            ),
            "skipped_stages": sum(
                1
                for plan in plans
                for stage in plan.stages
                if stage.status == "skipped"
            ),
        }
        return {
            "schema_version": "1.0",
            "title": title,
            "summary": summary,
            "targets": targets,
        }

    def analyze_credentials(self, payload: object) -> dict[str, Any]:
        """Analyze credential observations for weak-password indicators.

        Pure, local evaluation: no network access, no persistent state, and
        no secret material leaves the request. All structure is validated
        first (including duplicate attempt ids and policy secrets); only then
        are attempt targets checked against the allow/deny scope. Raises
        ValueError on malformed input and ScopeViolationError when any target
        is out of scope; never returns partial results.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "policy", "attempts"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)
        policy = _parse_credential_policy(payload["policy"])

        raw_attempts = payload["attempts"]
        if not isinstance(raw_attempts, list):
            raise ValueError("field attempts must be an array")
        attempts = [
            _parse_credential_attempt(raw, i)
            for i, raw in enumerate(raw_attempts)
        ]
        self._require_unique_ids(
            (attempt.id for attempt in attempts), "attempt"
        )

        # Scope gate: every attempt target must be authorized before any
        # analysis happens; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (attempt.target for attempt in attempts),
            allow_rules,
            deny_rules,
        )

        findings = [
            finding
            for attempt in attempts
            if (finding := self._credential_finding(attempt, policy)) is not None
        ]
        return {"findings": findings}

    @staticmethod
    def _credential_finding(
        attempt: _CredentialAttempt, policy: _CredentialPolicy
    ) -> dict[str, Any] | None:
        """Evaluate one authenticated attempt; never embed secret material."""
        if not attempt.authenticated:
            return None
        secret = attempt.secret
        codes: list[str] = []
        if secret == "":
            codes.append("empty_secret")
        if secret == attempt.username:
            codes.append("username_equals_secret")
        if secret in policy.weak_secrets:
            codes.append("dictionary_secret")
        # Length counts Unicode code points, not UTF-16/UTF-8 units.
        if len(secret) < policy.min_length:
            codes.append("short_secret")
        if not codes:
            return None
        severity = _CREDENTIAL_SEVERITY[codes[0]]
        for code in codes[1:]:
            candidate = _CREDENTIAL_SEVERITY[code]
            if _SEVERITY_RANK[candidate] > _SEVERITY_RANK[severity]:
                severity = candidate
        return {
            "attempt_id": attempt.id,
            "target": attempt.target.text,
            "port": attempt.port,
            "transport": attempt.transport,
            "service": attempt.service,
            "username": attempt.username,
            "severity": severity,
            "weakness_codes": codes,
        }

    @staticmethod
    def _require_unique_ids(ids: Any, what: str) -> None:
        seen: set[str] = set()
        for item in ids:
            if item in seen:
                raise ValueError(f"duplicate {what} id: {item!r}")
            seen.add(item)

    def generate_payloads(self, payload: object) -> dict[str, Any]:
        """Generate deterministic, offline encoding variants of templates.

        Pure, local evaluation: no network access, no payload execution, no
        persistent state. All structure is validated first (including
        duplicate ids and template/variable errors); only then is the single
        target checked against the allow/deny scope. Raises ValueError on
        malformed input and ScopeViolationError when the target is out of
        scope; never returns partial results.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "target", "items"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)
        target = _parse_entry(payload["target"], allow_wildcard=False)

        raw_items = payload["items"]
        if not isinstance(raw_items, list):
            raise ValueError("field items must be an array")
        items = [_parse_payload_item(raw, i) for i, raw in enumerate(raw_items)]
        self._require_unique_ids((item.id for item in items), "item")

        # Scope gate runs only after the whole request is structurally valid;
        # even an empty items list must have its target authorized.
        allowed, reason, _ = self._evaluate(target, allow_rules, deny_rules)
        if not allowed:
            raise ScopeViolationError(
                f"target {target.text} out of scope: {reason}"
            )

        generated: list[dict[str, Any]] = []
        for item in items:
            for variant in item.variants:
                value = item.rendered
                for step in variant.steps:
                    value = _PAYLOAD_TRANSFORMS[step](value)
                generated.append(
                    {
                        "item_id": item.id,
                        "variant_id": variant.id,
                        "target": target.text,
                        "steps": list(variant.steps),
                        "value": value,
                    }
                )
        return {"generated": generated}

    def compute_escalation_paths(self, payload: object) -> dict[str, Any]:
        """Compute best paths from start sessions to privilege goals.

        Pure, local evaluation: no network access, no persistent state. All
        structure is validated first; only then is the normalized target of
        every session and goal checked against the allow/deny scope. Raises
        ValueError on malformed input and ScopeViolationError when any target
        is out of scope; never returns partial paths.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "sessions", "transitions", "starts", "goals"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)

        for key in ("sessions", "transitions", "starts", "goals"):
            if not isinstance(payload[key], list):
                raise ValueError(f"field {key} must be an array")

        sessions = [
            _parse_escalation_session(raw, i)
            for i, raw in enumerate(payload["sessions"])
        ]
        self._require_unique_ids((session.id for session in sessions), "session")
        transitions = [
            _parse_escalation_transition(raw, i)
            for i, raw in enumerate(payload["transitions"])
        ]
        self._require_unique_ids(
            (transition.id for transition in transitions), "transition"
        )
        goals = [
            _parse_escalation_goal(raw, i) for i, raw in enumerate(payload["goals"])
        ]
        self._require_unique_ids((goal.id for goal in goals), "goal")

        session_ids = {session.id for session in sessions}
        for i, transition in enumerate(transitions):
            if transition.source not in session_ids:
                raise ValueError(
                    f"transitions[{i}].from references unknown session: "
                    f"{transition.source!r}"
                )
            if transition.destination not in session_ids:
                raise ValueError(
                    f"transitions[{i}].to references unknown session: "
                    f"{transition.destination!r}"
                )

        seen_starts: set[str] = set()
        for i, start in enumerate(payload["starts"]):
            if not isinstance(start, str) or not start:
                raise ValueError(f"starts[{i}] must be a non-empty string")
            if start in seen_starts:
                raise ValueError(f"starts has duplicate session id: {start!r}")
            seen_starts.add(start)
            if start not in session_ids:
                raise ValueError(
                    f"starts[{i}] references unknown session: {start!r}"
                )

        # Scope gate: every session and goal target must be authorized before
        # any path is computed; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (session.target for session in sessions), allow_rules, deny_rules
        )
        self._assert_targets_in_scope(
            (goal.target for goal in goals), allow_rules, deny_rules
        )

        session_pos = {session.id: i for i, session in enumerate(sessions)}
        transition_pos = {transition.id: i for i, transition in enumerate(transitions)}
        start_pos = {start: i for i, start in enumerate(payload["starts"])}
        outgoing: dict[str, list[_EscalationTransition]] = {
            session.id: [] for session in sessions
        }
        for transition in transitions:
            outgoing[transition.source].append(transition)
        sessions_by_id = {session.id: session for session in sessions}

        paths = [
            self._best_escalation_path(
                goal,
                sessions_by_id,
                outgoing,
                start_pos,
                session_pos,
                transition_pos,
            )
            for goal in goals
        ]
        return {"paths": paths}

    @staticmethod
    def _best_escalation_path(
        goal: _EscalationGoal,
        sessions_by_id: dict[str, _EscalationSession],
        outgoing: dict[str, list[_EscalationTransition]],
        start_pos: dict[str, int],
        session_pos: dict[str, int],
        transition_pos: dict[str, int],
    ) -> dict[str, Any]:
        """Multi-source Dijkstra ordered by the full path tie-break tuple.

        A route label is (total cost, transition count, start input position,
        tuple of transition input positions, end session input position).
        Every transition adds positive cost, so labels strictly grow along an
        edge and the heap settles routes in non-decreasing label order; the
        first settled session that satisfies the goal carries the best label,
        since replacing a node's prefix by a smaller label keeps every suffix
        comparison smaller.
        """
        goal_rank = _PRIVILEGE_RANK[goal.min_privilege]
        goal_text = goal.target.text

        def satisfies(session: _EscalationSession) -> bool:
            return (
                session.target.text == goal_text
                and _PRIVILEGE_RANK[session.privilege] >= goal_rank
            )

        # label[node] is the smallest label of a route reaching the node;
        # parent[node] is the (incoming transition, predecessor) of that route.
        labels: dict[str, tuple[Any, ...]] = {}
        parent: dict[str, tuple[_EscalationTransition, str] | None] = {}
        heap: list[tuple[Any, ...]] = []
        for start_id, start_index in start_pos.items():
            label = (0, 0, start_index, (), session_pos[start_id])
            labels[start_id] = label
            parent[start_id] = None
            heapq.heappush(heap, label + (start_id,))

        answer_node: str | None = None
        while heap:
            entry = heapq.heappop(heap)
            label = entry[:-1]
            node = entry[-1]
            if labels.get(node) != label:
                continue  # superseded by a smaller label for the same node
            if satisfies(sessions_by_id[node]):
                answer_node = node
                break
            for transition in outgoing[node]:
                neighbor = transition.destination
                new_label = (
                    label[0] + transition.cost,
                    label[1] + 1,
                    label[2],
                    label[3] + (transition_pos[transition.id],),
                    session_pos[neighbor],
                )
                current = labels.get(neighbor)
                if current is None or new_label < current:
                    labels[neighbor] = new_label
                    parent[neighbor] = (transition, node)
                    heapq.heappush(heap, new_label + (neighbor,))

        if answer_node is None:
            return {
                "goal_id": goal.id,
                "target": goal.target.text,
                "min_privilege": goal.min_privilege,
                "status": "unreachable",
                "path": None,
            }

        route_transitions: list[_EscalationTransition] = []
        route_nodes = [answer_node]
        node = answer_node
        while (link := parent[node]) is not None:
            transition, predecessor = link
            route_transitions.append(transition)
            route_nodes.append(predecessor)
            node = predecessor
        route_nodes.reverse()
        route_transitions.reverse()
        return {
            "goal_id": goal.id,
            "target": goal.target.text,
            "min_privilege": goal.min_privilege,
            "status": "reachable",
            "path": {
                "start_session_id": route_nodes[0],
                "end_session_id": answer_node,
                "total_cost": labels[answer_node][0],
                "session_ids": route_nodes,
                "transition_ids": [transition.id for transition in route_transitions],
            },
        }
