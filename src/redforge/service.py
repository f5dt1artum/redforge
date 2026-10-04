"""Core service surface for RedForge.

The frozen baseline only reports process health. Later work adds the real
capabilities described in README.md behind this module; keep the public
surface here backward compatible.
"""

from __future__ import annotations

import base64
import hashlib
import heapq
import ipaddress
import math
import re
from collections import deque
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
_RATE_LIMIT_POLICY_FIELDS = frozenset({"window_ms", "max_requests", "group_by"})
_RATE_LIMIT_ATTEMPT_FIELDS = frozenset(
    {"id", "target", "route", "identity", "timestamp_ms"}
)
_SCHEDULE_REQUEST_FIELDS = frozenset(
    {"id", "target", "route", "earliest_ms", "depends_on"}
)
_SAFETY_POLICY_FIELDS = frozenset(
    {"enabled", "window_ms", "max_actions_per_target", "blocked_kinds"}
)
_SAFETY_ACTION_FIELDS = frozenset({"id", "target", "kind", "scheduled_ms"})
_AUDIT_EVENT_FIELDS = frozenset({"id", "target", "kind", "outcome", "occurred_ms"})
_AUDIT_FIELDS = frozenset({"exercise_id", "records", "head_hash"})
_WEB_OBSERVATION_FIELDS = frozenset({"id", "target", "scheme", "headers"})
_DISCOVER_RECORD_FIELDS = frozenset({"id", "name", "type", "value"})
_AUDIT_RECORD_FIELDS = frozenset(
    {
        "id",
        "target",
        "kind",
        "outcome",
        "occurred_ms",
        "sequence",
        "previous_hash",
        "hash",
    }
)
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_ZERO_HASH = "0" * 64

RATE_LIMIT_GROUPINGS = ("target", "target_route")

# Categories analyzable by the offline web-response security analyzer.
WEB_SECURITY_CHECKS = ("cors", "cookie", "security_headers")
WEB_SCHEMES = ("http", "https")

# DNS record types accepted by the offline asset-discovery endpoint.
DISCOVER_RECORD_TYPES = ("A", "AAAA", "CNAME")

# Fixed emission order of the findings produced by one security_headers run.
_SECURITY_HEADER_FINDING_ORDER = (
    ("hsts_missing_or_invalid", "high"),
    ("csp_missing", "medium"),
    ("clickjacking_unprotected", "medium"),
    ("nosniff_missing", "low"),
)
_ASCII_DIGITS = frozenset("0123456789")

SAFETY_KINDS = ("discovery", "verification", "exploitation", "credential", "privilege")

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


@dataclass(frozen=True)
class _RateLimitPolicy:
    """A validated rate-limit-analysis policy."""

    window_ms: int
    max_requests: int
    group_by: str


@dataclass(frozen=True)
class _RateLimitAttempt:
    """A validated rate-limit request observation.

    target is the parsed scope entry; its text attribute is the normalized
    form reported back in alerts.
    """

    id: str
    target: _Entry
    route: str
    identity: str
    timestamp_ms: int


def _parse_rate_limit_policy(raw: object) -> _RateLimitPolicy:
    obj = _require_fields(raw, _RATE_LIMIT_POLICY_FIELDS, "policy")
    window_ms = obj["window_ms"]
    if not _is_int(window_ms) or window_ms < 1:
        raise ValueError("policy.window_ms must be a positive integer")
    max_requests = obj["max_requests"]
    if not _is_int(max_requests) or max_requests < 1:
        raise ValueError("policy.max_requests must be a positive integer")
    group_by = obj["group_by"]
    if group_by not in RATE_LIMIT_GROUPINGS:
        raise ValueError(f"policy.group_by must be one of {RATE_LIMIT_GROUPINGS}")
    return _RateLimitPolicy(window_ms, max_requests, group_by)


def _parse_rate_limit_attempt(raw: object, index: int) -> _RateLimitAttempt:
    what = f"attempts[{index}]"
    obj = _require_fields(raw, _RATE_LIMIT_ATTEMPT_FIELDS, what)
    attempt_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    route = obj["route"]
    if not isinstance(route, str) or not route.startswith("/"):
        raise ValueError(
            f"{what}.route must be a non-empty string starting with '/'"
        )
    identity = _non_empty_str(obj["identity"], f"{what}.identity")
    timestamp_ms = obj["timestamp_ms"]
    if not _is_int(timestamp_ms) or timestamp_ms < 0:
        raise ValueError(f"{what}.timestamp_ms must be a non-negative integer")
    return _RateLimitAttempt(attempt_id, target, route, identity, timestamp_ms)


@dataclass(frozen=True)
class _ScheduledRequest:
    """A validated request to schedule.

    target is the parsed scope entry; its text attribute is the normalized
    form reported back in the schedule.
    """

    id: str
    target: _Entry
    route: str
    earliest_ms: int
    depends_on: tuple[str, ...]


def _parse_scheduled_request(raw: object, index: int) -> _ScheduledRequest:
    what = f"requests[{index}]"
    obj = _require_fields(raw, _SCHEDULE_REQUEST_FIELDS, what)
    request_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    route = obj["route"]
    if not isinstance(route, str) or not route.startswith("/"):
        raise ValueError(
            f"{what}.route must be a non-empty string starting with '/'"
        )
    earliest_ms = obj["earliest_ms"]
    if not _is_int(earliest_ms) or earliest_ms < 0:
        raise ValueError(f"{what}.earliest_ms must be a non-negative integer")
    raw_depends_on = obj["depends_on"]
    if not isinstance(raw_depends_on, list):
        raise ValueError(f"{what}.depends_on must be an array")
    depends_on: list[str] = []
    seen_deps: set[str] = set()
    for dep in raw_depends_on:
        if not isinstance(dep, str) or not dep:
            raise ValueError(
                f"{what}.depends_on must contain only non-empty strings"
            )
        if dep in seen_deps:
            raise ValueError(f"{what}.depends_on has duplicate entry: {dep!r}")
        seen_deps.add(dep)
        depends_on.append(dep)
    return _ScheduledRequest(
        request_id, target, route, earliest_ms, tuple(depends_on)
    )


@dataclass(frozen=True)
class _SafetyPolicy:
    """A validated exercise safety-evaluation policy."""

    enabled: bool
    window_ms: int
    max_actions_per_target: int
    blocked_kinds: frozenset[str]


@dataclass(frozen=True)
class _SafetyAction:
    """A validated exercise action awaiting a safety decision.

    target is the parsed scope entry; its text attribute is the normalized
    form reported back in decisions.
    """

    id: str
    target: _Entry
    kind: str
    scheduled_ms: int


def _parse_safety_policy(raw: object) -> _SafetyPolicy:
    obj = _require_fields(raw, _SAFETY_POLICY_FIELDS, "policy")
    enabled = obj["enabled"]
    if not isinstance(enabled, bool):
        raise ValueError("policy.enabled must be a boolean")
    window_ms = obj["window_ms"]
    if not _is_int(window_ms) or window_ms < 1:
        raise ValueError("policy.window_ms must be a positive integer")
    max_actions = obj["max_actions_per_target"]
    if not _is_int(max_actions) or max_actions < 1:
        raise ValueError("policy.max_actions_per_target must be a positive integer")
    raw_blocked = obj["blocked_kinds"]
    if not isinstance(raw_blocked, list):
        raise ValueError("policy.blocked_kinds must be an array")
    blocked: list[str] = []
    seen: set[str] = set()
    for kind in raw_blocked:
        if kind not in SAFETY_KINDS:
            raise ValueError(
                f"policy.blocked_kinds must contain only kinds from {SAFETY_KINDS}"
            )
        if kind in seen:
            raise ValueError(f"policy.blocked_kinds has duplicate entry: {kind!r}")
        seen.add(kind)
        blocked.append(kind)
    return _SafetyPolicy(enabled, window_ms, max_actions, frozenset(blocked))


def _parse_safety_action(raw: object, index: int) -> _SafetyAction:
    what = f"actions[{index}]"
    obj = _require_fields(raw, _SAFETY_ACTION_FIELDS, what)
    action_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    kind = obj["kind"]
    if kind not in SAFETY_KINDS:
        raise ValueError(f"{what}.kind must be one of {SAFETY_KINDS}")
    scheduled_ms = obj["scheduled_ms"]
    if not _is_int(scheduled_ms) or scheduled_ms < 0:
        raise ValueError(f"{what}.scheduled_ms must be a non-negative integer")
    return _SafetyAction(action_id, target, kind, scheduled_ms)


@dataclass(frozen=True)
class _AuditEvent:
    """A validated exercise event for the deterministic audit chain.

    target is the parsed scope entry (never a wildcard); its text attribute
    is the normalized form embedded in audit records.
    """

    id: str
    target: _Entry
    kind: str
    outcome: str
    occurred_ms: int


def _parse_audit_event(raw: object, index: int) -> _AuditEvent:
    what = f"events[{index}]"
    obj = _require_fields(raw, _AUDIT_EVENT_FIELDS, what)
    event_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    kind = _non_empty_str(obj["kind"], f"{what}.kind")
    outcome = _non_empty_str(obj["outcome"], f"{what}.outcome")
    occurred_ms = obj["occurred_ms"]
    if not _is_int(occurred_ms) or occurred_ms < 0:
        raise ValueError(f"{what}.occurred_ms must be a non-negative integer")
    return _AuditEvent(event_id, target, kind, outcome, occurred_ms)


@dataclass(frozen=True)
class _WebObservation:
    """A validated offline web-response observation.

    target is the parsed scope entry (never a wildcard); its text attribute
    is the normalized form reported back in findings. headers maps the
    original header names to lists of values, kept verbatim in input order;
    name comparisons are always case-insensitive.
    """

    id: str
    target: _Entry
    scheme: str
    headers: dict[str, tuple[str, ...]]


def _parse_web_observation(raw: object, index: int) -> _WebObservation:
    what = f"observations[{index}]"
    obj = _require_fields(raw, _WEB_OBSERVATION_FIELDS, what)
    observation_id = _non_empty_str(obj["id"], f"{what}.id")
    target = _parse_entry(obj["target"], allow_wildcard=False)
    scheme = obj["scheme"]
    if scheme not in WEB_SCHEMES:
        raise ValueError(f"{what}.scheme must be one of {WEB_SCHEMES}")
    raw_headers = obj["headers"]
    if not isinstance(raw_headers, dict):
        raise ValueError(f"{what}.headers must be an object")
    headers: dict[str, tuple[str, ...]] = {}
    for name, values in raw_headers.items():
        if not isinstance(name, str) or not name:
            raise ValueError(f"{what}.headers must map non-empty header names")
        if not isinstance(values, list) or not values:
            raise ValueError(
                f"{what}.headers[{name!r}] must be a non-empty array of strings"
            )
        for value in values:
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"{what}.headers[{name!r}] must contain only non-empty strings"
                )
        headers[name] = tuple(values)
    return _WebObservation(observation_id, target, scheme, headers)


@dataclass(frozen=True)
class _DnsRecord:
    """A validated offline DNS record.

    name is the normalized record hostname. For A/AAAA records value is the
    parsed ip_address; for CNAME records value is the normalized hostname.
    """

    id: str
    name: str
    type: str
    value: Any


def _parse_discover_record(raw: object, index: int) -> _DnsRecord:
    what = f"records[{index}]"
    obj = _require_fields(raw, _DISCOVER_RECORD_FIELDS, what)
    record_id = _non_empty_str(obj["id"], f"{what}.id")
    name = _parse_entry(obj["name"], allow_wildcard=False)
    if name.kind != "host":
        raise ValueError(f"{what}.name must be a hostname")
    record_type = obj["type"]
    if record_type not in DISCOVER_RECORD_TYPES:
        raise ValueError(f"{what}.type must be one of {DISCOVER_RECORD_TYPES}")
    value_entry = _parse_entry(obj["value"], allow_wildcard=False)
    if record_type == "A":
        if value_entry.kind != "ip" or value_entry.value.version != 4:
            raise ValueError(f"{what}.value must be an IPv4 address")
    elif record_type == "AAAA":
        if value_entry.kind != "ip" or value_entry.value.version != 6:
            raise ValueError(f"{what}.value must be an IPv6 address")
    elif value_entry.kind != "host":
        raise ValueError(f"{what}.value must be a hostname")
    return _DnsRecord(record_id, name.text, record_type, value_entry)


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


def _jcs_number(value: float) -> str:
    """Serialize a float the way ECMAScript's Number::toString does (JCS).

    RFC 8785 §3.2.2.3 adopts the ES2018 algorithm (with the Note 2
    enhancement): the shortest round-trippable decimal, fixed notation for
    -6 <= exponent <= 20, scientific otherwise (the exponent sign is kept,
    e.g. 1e+21), and -0 rendered as 0.
    """
    if isinstance(value, int):
        value = float(value)
    if value == 0:
        return "0"
    text = repr(value)
    mantissa, _, exponent = text.partition("e")
    if exponent:
        exp = int(exponent)
        text = mantissa
    else:
        exp = 0
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    int_part, _, frac_part = text.partition(".")
    # repr() tags an integral float with ".0"; those zeros are formatting,
    # not significant digits of the shortest round-trip representation.
    frac_part = frac_part.rstrip("0")
    digits = (int_part + frac_part).lstrip("0")
    int_digits = int_part.lstrip("0")
    if int_digits:
        # Exponent of the most significant digit in the integer part.
        n = len(int_digits) - 1 + exp
    else:
        # First significant digit sits after the point; count leading zeros.
        leading_zeros = len(frac_part) - len(frac_part.lstrip("0"))
        n = -leading_zeros - 1 + exp
    decimal_at = n + 1  # number of significant digits before the point

    if -6 <= n <= 20:
        if decimal_at <= 0:
            result = "0." + "0" * (-decimal_at) + digits
        elif decimal_at >= len(digits):
            result = digits + "0" * (decimal_at - len(digits))
        else:
            result = digits[:decimal_at] + "." + digits[decimal_at:]
    else:
        head = digits[0]
        rest = digits[1:]
        coefficient = head + ("." + rest if rest else "")
        result = f"{coefficient}e{n:+d}"
    return "-" + result if negative else result


def _jcs_escape(text: str) -> str:
    """Escape a JSON string per JCS: minimal escapes, lowercase hex."""
    pieces = ['"']
    for char in text:
        codepoint = ord(char)
        if char == '"':
            pieces.append('\\"')
        elif char == "\\":
            pieces.append("\\\\")
        elif codepoint == 0x08:
            pieces.append("\\b")
        elif codepoint == 0x0C:
            pieces.append("\\f")
        elif codepoint == 0x0A:
            pieces.append("\\n")
        elif codepoint == 0x0D:
            pieces.append("\\r")
        elif codepoint == 0x09:
            pieces.append("\\t")
        elif codepoint < 0x20:
            pieces.append(f"\\u{codepoint:04x}")
        else:
            pieces.append(char)
    pieces.append('"')
    return "".join(pieces)


def _jcs_sort_key(name: str) -> tuple:
    """UTF-16 code-unit ordering for object member names (JCS §3.2.3)."""
    encoded = name.encode("utf-16-be")
    return tuple(encoded[i] << 8 | encoded[i + 1] for i in range(0, len(encoded), 2))


def _jcs_serialize(value: object) -> str:
    """Serialize a JSON-compatible Python value per RFC 8785."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_escape(value)
    if isinstance(value, int):
        return _jcs_number(float(value))
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN and Infinity are not representable in JSON")
        return _jcs_number(value)
    if isinstance(value, dict):
        members = []
        for key in sorted(value, key=_jcs_sort_key):
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
            members.append(_jcs_escape(key) + ":" + _jcs_serialize(value[key]))
        return "{" + ",".join(members) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_serialize(item) for item in value) + "]"
    raise ValueError(f"value is not JSON-compatible: {type(value).__name__}")


def _jcs_bytes(value: object) -> bytes:
    """RFC 8785 canonical bytes (UTF-8) for a JSON-compatible value."""
    return _jcs_serialize(value).encode("utf-8")


def _audit_record_hash(record: dict[str, Any], exercise_id: str) -> str:
    """SHA-256 over the RFC 8785 bytes of record-minus-hash plus exercise_id."""
    payload = {key: value for key, value in record.items() if key != "hash"}
    payload["exercise_id"] = exercise_id
    return hashlib.sha256(_jcs_bytes(payload)).hexdigest()


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

    def discover_assets(self, payload: object) -> dict[str, Any]:
        """Deterministically expand authorized seeds using offline DNS records.

        Pure, local evaluation: no network access, no probing, no persistent
        state. Every structure, field, identifier, seed target and record
        value is validated first (any failure raises ValueError); only then
        are the seeds and the targets actually reached within max_depth
        checked against the allow/deny scope, and a single rejection raises
        ScopeViolationError. Never returns partial results, and the same
        input always produces the same assets.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "seeds", "records", "max_depth"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)

        max_depth = payload["max_depth"]
        if not _is_int(max_depth) or not 0 <= max_depth <= 32:
            raise ValueError("field max_depth must be an integer between 0 and 32")

        raw_seeds = payload["seeds"]
        if not isinstance(raw_seeds, list):
            raise ValueError("field seeds must be an array")
        seeds: list[_Entry] = []
        seen_seed_targets: set[str] = set()
        for i, raw_seed in enumerate(raw_seeds):
            what = f"seeds[{i}]"
            if not isinstance(raw_seed, str) or not raw_seed:
                raise ValueError(f"{what} must be a non-empty string")
            entry = _parse_entry(raw_seed, allow_wildcard=False)
            if entry.kind == "network":
                raise ValueError(f"{what} must be a hostname or a single IP")
            if entry.text in seen_seed_targets:
                raise ValueError(f"duplicate seed after normalization: {entry.text!r}")
            seen_seed_targets.add(entry.text)
            seeds.append(entry)

        raw_records = payload["records"]
        if not isinstance(raw_records, list):
            raise ValueError("field records must be an array")
        records = [
            _parse_discover_record(raw, i) for i, raw in enumerate(raw_records)
        ]
        self._require_unique_ids((record.id for record in records), "record")

        # Index records by normalized name, preserving their input order.
        records_by_name: dict[str, list[_DnsRecord]] = {}
        for record in records:
            records_by_name.setdefault(record.name, []).append(record)

        # Breadth-first traversal seeded at depth 0. discovered maps each
        # normalized target to its parsed entry plus shortest, first-
        # discovered path metadata; ordered keeps BFS first-discovery order.
        discovered: dict[str, dict[str, Any]] = {}
        ordered: list[_Entry] = []
        queue: deque[tuple[_Entry, int]] = deque()
        for seed in seeds:
            discovered[seed.text] = {
                "entry": seed,
                "kind": "hostname" if seed.kind == "host" else "ip",
                "depth": 0,
                "source": None,
                "record_id": None,
            }
            ordered.append(seed)
            queue.append((seed, 0))

        while queue:
            current, depth = queue.popleft()
            if current.kind != "host" or depth >= max_depth:
                continue
            for record in records_by_name.get(current.text, ()):
                child = record.value
                if child.text in discovered:
                    continue  # shortest / first path already recorded
                discovered[child.text] = {
                    "entry": child,
                    "kind": "hostname" if child.kind == "host" else "ip",
                    "depth": depth + 1,
                    "source": current.text,
                    "record_id": record.id,
                }
                ordered.append(child)
                queue.append((child, depth + 1))

        # Scope gate over seeds and reached targets only; record values that
        # were never traversed are deliberately excluded.
        self._assert_targets_in_scope(
            (discovered[entry.text]["entry"] for entry in ordered),
            allow_rules,
            deny_rules,
        )

        assets = [
            {
                "target": entry.text,
                "kind": discovered[entry.text]["kind"],
                "depth": discovered[entry.text]["depth"],
                "source": discovered[entry.text]["source"],
                "record_id": discovered[entry.text]["record_id"],
            }
            for entry in ordered
        ]
        return {"assets": assets}

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

    def analyze_rate_limit(self, payload: object) -> dict[str, Any]:
        """Detect rate-limit saturation and distributed identity-splitting.

        Pure, local evaluation: no network access, no persistent state. All
        structure is validated first (including duplicate attempt ids); only
        then are attempt targets checked against the allow/deny scope. Raises
        ValueError on malformed input and ScopeViolationError when any target
        is out of scope; never returns partial results. The same input always
        produces the same alerts.
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
        policy = _parse_rate_limit_policy(payload["policy"])

        raw_attempts = payload["attempts"]
        if not isinstance(raw_attempts, list):
            raise ValueError("field attempts must be an array")
        attempts = [
            _parse_rate_limit_attempt(raw, i)
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

        return {"alerts": self._rate_limit_alerts(attempts, policy)}

    @staticmethod
    def _rate_limit_alerts(
        attempts: list[_RateLimitAttempt], policy: _RateLimitPolicy
    ) -> list[dict[str, Any]]:
        """Group attempts into fixed windows and flag groups over the limit.

        Groups key on the normalized target and the window start, plus the
        case-sensitive route when the policy groups by target_route. Only a
        group whose total exceeds max_requests alerts; the kind is
        distributed_bypass when at least two identities share the group and
        no single identity exceeds the limit on its own.
        """
        target_pos: dict[str, int] = {}
        route_pos: dict[str, int] = {}
        groups: dict[tuple[Any, ...], list[int]] = {}
        for index, attempt in enumerate(attempts):
            target_pos.setdefault(attempt.target.text, index)
            route_pos.setdefault(attempt.route, index)
            window_start = (
                attempt.timestamp_ms // policy.window_ms
            ) * policy.window_ms
            if policy.group_by == "target_route":
                key: tuple[Any, ...] = (
                    attempt.target.text,
                    attempt.route,
                    window_start,
                )
            else:
                key = (attempt.target.text, None, window_start)
            groups.setdefault(key, []).append(index)

        alerts: list[dict[str, Any]] = []
        for (target, route, window_start), indexes in groups.items():
            if len(indexes) <= policy.max_requests:
                continue
            identity_counts: dict[str, int] = {}
            for index in indexes:
                identity = attempts[index].identity
                identity_counts[identity] = identity_counts.get(identity, 0) + 1
            distributed = len(identity_counts) >= 2 and all(
                count <= policy.max_requests
                for count in identity_counts.values()
            )
            # indexes are in input order, so the stable sort breaks
            # timestamp ties by input position.
            ordered = sorted(indexes, key=lambda i: attempts[i].timestamp_ms)
            alerts.append(
                {
                    "target": target,
                    "route": route,
                    "window_start_ms": window_start,
                    "window_end_ms": window_start + policy.window_ms,
                    "total_requests": len(indexes),
                    "identity_counts": [
                        {"identity": identity, "count": count}
                        for identity, count in identity_counts.items()
                    ],
                    "kind": (
                        "distributed_bypass" if distributed else "direct_excess"
                    ),
                    "attempt_ids": [attempts[i].id for i in ordered],
                    "_sort": (
                        window_start,
                        target_pos[target],
                        route_pos[route] if route is not None else 0,
                    ),
                }
            )
        alerts.sort(key=lambda alert: alert["_sort"])
        for alert in alerts:
            del alert["_sort"]
        return alerts

    def schedule_requests(self, payload: object) -> dict[str, Any]:
        """Compute the earliest compliant execution time for pending requests.

        Pure, local evaluation: no network access, no request dispatch, no
        payload execution, and no persistent state. All structure is
        validated first (including duplicate ids, unknown or duplicate
        dependencies, self-dependencies, and dependency cycles); only then
        are request targets checked against the allow/deny scope. Raises
        ValueError on malformed input and ScopeViolationError when any target
        is out of scope; never returns a partial schedule. The same input
        always produces the same schedule.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "policy", "requests"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)
        policy = _parse_rate_limit_policy(payload["policy"])

        raw_requests = payload["requests"]
        if not isinstance(raw_requests, list):
            raise ValueError("field requests must be an array")
        requests = [
            _parse_scheduled_request(raw, i) for i, raw in enumerate(raw_requests)
        ]
        self._require_unique_ids(
            (request.id for request in requests), "request"
        )
        # Structural validation of the dependency graph (unknown ids,
        # self-dependencies, cycles) finishes before the scope gate.
        ordered_requests = self._resolve_request_order(requests)

        # Scope gate: every request target must be authorized before any
        # scheduling happens; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (request.target for request in requests),
            allow_rules,
            deny_rules,
        )

        schedule = self._build_schedule(
            ordered_requests, policy, {r.id: i for i, r in enumerate(requests)}
        )
        # Report by scheduled_ms ascending; ties keep the stable topological
        # (input-position respecting) order.
        schedule.sort(key=lambda item: (item["scheduled_ms"], item["_pos"]))
        for item in schedule:
            del item["_pos"]
        return {"schedule": schedule}

    @staticmethod
    def _resolve_request_order(
        requests: list[_ScheduledRequest],
    ) -> list[_ScheduledRequest]:
        """Topologically order requests; same level keeps input order.

        Raises ValueError on self-references, unknown ids, or cycles.
        """
        known = {request.id for request in requests}
        for request in requests:
            for dep in request.depends_on:
                if dep == request.id:
                    raise ValueError(
                        f"request {request.id!r} depends on itself"
                    )
                if dep not in known:
                    raise ValueError(
                        f"request {request.id!r} depends on unknown id: "
                        f"{dep!r}"
                    )
        remaining = list(requests)
        done: set[str] = set()
        ordered: list[_ScheduledRequest] = []
        while remaining:
            ready_now = [
                request
                for request in remaining
                if all(dep in done for dep in request.depends_on)
            ]
            if not ready_now:
                raise ValueError("request dependencies form a cycle")
            for request in ready_now:
                done.add(request.id)
            ordered.extend(ready_now)
            remaining = [
                request for request in remaining if request.id not in done
            ]
        return ordered

    @staticmethod
    def _build_schedule(
        ordered_requests: list[_ScheduledRequest],
        policy: _RateLimitPolicy,
        input_positions: dict[str, int],
    ) -> list[dict[str, Any]]:
        """Place each request into the earliest non-saturated fixed window.

        Candidates are walked in stable topological order, so input position
        decides every occupancy tie. Per group, each fixed window holds at
        most max_requests placements; a full window pushes the request to
        the next window start.
        """
        window_ms = policy.window_ms
        max_requests = policy.max_requests
        scheduled_at: dict[str, int] = {}
        # group -> {window_start: [request id, ...]} in placement order.
        occupancy: dict[Any, dict[int, list[str]]] = {}
        results: list[dict[str, Any]] = []

        for request in ordered_requests:
            candidate = request.earliest_ms
            for dep in request.depends_on:
                if scheduled_at[dep] > candidate:
                    candidate = scheduled_at[dep]
            group: Any
            if policy.group_by == "target_route":
                group = (request.target.text, request.route)
            else:
                group = request.target.text
            group_windows = occupancy.setdefault(group, {})
            window_start = (candidate // window_ms) * window_ms
            candidate_window = window_start
            while len(group_windows.get(window_start, ())) >= max_requests:
                window_start += window_ms
            group_windows.setdefault(window_start, []).append(request.id)
            # Room in the candidate's own window: execute at the candidate
            # time; a bumped request executes at the next window start.
            scheduled_ms = (
                candidate if window_start == candidate_window else window_start
            )
            scheduled_at[request.id] = scheduled_ms
            results.append(
                {
                    "id": request.id,
                    "target": request.target.text,
                    "route": request.route,
                    "scheduled_ms": scheduled_ms,
                    "window_start_ms": window_start,
                    "depends_on": list(request.depends_on),
                    "_pos": input_positions[request.id],
                }
            )
        return results

    def safety_evaluate(self, payload: object) -> dict[str, Any]:
        """Decide whether each planned exercise action may proceed.

        Pure, local evaluation: no network access, no action execution, no
        persistent state. All structure is validated first (including
        duplicate action ids and duplicate blocked kinds); only then are
        action targets checked against the allow/deny scope. Raises
        ValueError on malformed input and ScopeViolationError when any target
        is out of scope; never returns partial decisions. The same input
        always produces the same decisions.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "policy", "actions"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)
        policy = _parse_safety_policy(payload["policy"])

        raw_actions = payload["actions"]
        if not isinstance(raw_actions, list):
            raise ValueError("field actions must be an array")
        actions = [
            _parse_safety_action(raw, i) for i, raw in enumerate(raw_actions)
        ]
        self._require_unique_ids((action.id for action in actions), "action")

        # Scope gate: every action target must be authorized before any
        # decision is made; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (action.target for action in actions),
            allow_rules,
            deny_rules,
        )

        return self._evaluate_safety(actions, policy)

    @staticmethod
    def _evaluate_safety(
        actions: list[_SafetyAction], policy: _SafetyPolicy
    ) -> dict[str, Any]:
        """Decide actions in input order against the safety policy.

        A disabled policy blocks everything with emergency_stop; otherwise a
        blocked kind is rejected before quota accounting. Remaining actions
        consume one slot of their normalized target's fixed window; the first
        max_actions_per_target per target per window pass, the rest are
        blocked with action_limit. emergency_stop and blocked_kind decisions
        never consume quota.
        """
        decisions: list[dict[str, Any]] = []
        occupancy: dict[tuple[str, int], int] = {}
        allowed_count = 0
        for action in actions:
            status = "allowed"
            reason: str | None = None
            if not policy.enabled:
                status, reason = "blocked", "emergency_stop"
            elif action.kind in policy.blocked_kinds:
                status, reason = "blocked", "blocked_kind"
            else:
                window_start = (
                    action.scheduled_ms // policy.window_ms
                ) * policy.window_ms
                key = (action.target.text, window_start)
                count = occupancy.get(key, 0)
                if count >= policy.max_actions_per_target:
                    status, reason = "blocked", "action_limit"
                else:
                    occupancy[key] = count + 1
            if reason is None:
                allowed_count += 1
            decisions.append(
                {
                    "id": action.id,
                    "target": action.target.text,
                    "kind": action.kind,
                    "scheduled_ms": action.scheduled_ms,
                    "status": status,
                    "reason": reason,
                }
            )
        return {
            "decisions": decisions,
            "summary": {
                "total": len(actions),
                "allowed": allowed_count,
                "blocked": len(actions) - allowed_count,
            },
        }

    def build_audit(self, payload: object) -> dict[str, Any]:
        """Build a deterministic, offline exercise audit chain.

        Pure, local evaluation: no network access, no action execution, no
        persistent state. All structure is validated first (including
        duplicate event ids and non-increasing timestamps); only then are
        event targets checked against the allow/deny scope. Raises
        ValueError on malformed input and ScopeViolationError when any target
        is out of scope; never returns a partial chain. The same input always
        produces the same records and hashes.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "exercise_id", "events"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)
        exercise_id = _non_empty_str(payload["exercise_id"], "exercise_id")

        raw_events = payload["events"]
        if not isinstance(raw_events, list):
            raise ValueError("field events must be an array")
        events = [_parse_audit_event(raw, i) for i, raw in enumerate(raw_events)]
        self._require_unique_ids((event.id for event in events), "event")
        for index in range(1, len(events)):
            if events[index].occurred_ms < events[index - 1].occurred_ms:
                raise ValueError(
                    f"events[{index}].occurred_ms decreases relative to input "
                    "order"
                )

        # Scope gate: every event target must be authorized before any record
        # is hashed; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (event.target for event in events), allow_rules, deny_rules
        )

        records: list[dict[str, Any]] = []
        previous_hash = _ZERO_HASH
        for sequence, event in enumerate(events):
            record = {
                "id": event.id,
                "target": event.target.text,
                "kind": event.kind,
                "outcome": event.outcome,
                "occurred_ms": event.occurred_ms,
                "sequence": sequence,
                "previous_hash": previous_hash,
            }
            record["hash"] = _audit_record_hash(record, exercise_id)
            records.append(record)
            previous_hash = record["hash"]
        head_hash = previous_hash if records else _ZERO_HASH
        return {
            "audit": {
                "exercise_id": exercise_id,
                "records": records,
                "head_hash": head_hash,
            }
        }

    def verify_audit(self, payload: object) -> dict[str, Any]:
        """Verify a deterministic exercise audit chain end to end.

        Pure, local evaluation: no network access, no action execution, no
        persistent state. Structure, hash formats, event-id uniqueness and
        timestamp ordering are validated strictly first (any failure is a
        ValueError); every normalized target then passes the allow/deny
        scope gate (an out-of-scope target is a ScopeViolationError). Only
        afterwards are sequence/previous_hash/hash/head_hash checked, and the
        first inconsistency is reported rather than raised.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "audit"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)
        audit = _require_fields(payload["audit"], _AUDIT_FIELDS, "audit")
        exercise_id = _non_empty_str(audit["exercise_id"], "audit.exercise_id")
        head_hash = audit["head_hash"]
        if not isinstance(head_hash, str) or not _HEX64_RE.fullmatch(head_hash):
            raise ValueError("audit.head_hash must be a 64-character lowercase hex string")

        raw_records = audit["records"]
        if not isinstance(raw_records, list):
            raise ValueError("audit.records must be an array")
        records = [
            self._parse_audit_record(raw, i)
            for i, raw in enumerate(raw_records)
        ]
        self._require_unique_ids(
            (record["id"] for record in records), "event"
        )
        for index in range(1, len(records)):
            if records[index]["occurred_ms"] < records[index - 1]["occurred_ms"]:
                raise ValueError(
                    f"audit.records[{index}].occurred_ms decreases relative to "
                    "input order"
                )

        # Scope gate over the normalized targets carried by the chain.
        targets = [
            _parse_entry(record["target"], allow_wildcard=False)
            for record in records
        ]
        self._assert_targets_in_scope(targets, allow_rules, deny_rules)

        checked = 0
        last_hash = _ZERO_HASH
        expected_previous = _ZERO_HASH
        for index, record in enumerate(records):
            if record["sequence"] != index:
                return self._verification_failure(
                    checked, last_hash, index, "sequence_mismatch"
                )
            if record["previous_hash"] != expected_previous:
                return self._verification_failure(
                    checked, last_hash, index, "previous_hash_mismatch"
                )
            if _audit_record_hash(record, exercise_id) != record["hash"]:
                return self._verification_failure(
                    checked, last_hash, index, "hash_mismatch"
                )
            checked += 1
            last_hash = record["hash"]
            expected_previous = record["hash"]
        expected_head = last_hash if records else _ZERO_HASH
        if head_hash != expected_head:
            return self._verification_failure(
                checked, last_hash, len(records), "head_hash_mismatch"
            )
        return {
            "verification": {
                "valid": True,
                "checked": checked,
                "head_hash": last_hash if records else _ZERO_HASH,
                "failure": None,
            }
        }

    @staticmethod
    def _parse_audit_record(raw: object, index: int) -> dict[str, Any]:
        what = f"audit.records[{index}]"
        obj = _require_fields(raw, _AUDIT_RECORD_FIELDS, what)
        event_id = _non_empty_str(obj["id"], f"{what}.id")
        target = _parse_entry(obj["target"], allow_wildcard=False)
        kind = _non_empty_str(obj["kind"], f"{what}.kind")
        outcome = _non_empty_str(obj["outcome"], f"{what}.outcome")
        occurred_ms = obj["occurred_ms"]
        if not _is_int(occurred_ms) or occurred_ms < 0:
            raise ValueError(f"{what}.occurred_ms must be a non-negative integer")
        sequence = obj["sequence"]
        if not _is_int(sequence) or sequence < 0:
            raise ValueError(f"{what}.sequence must be a non-negative integer")
        previous_hash = obj["previous_hash"]
        if not isinstance(previous_hash, str) or not _HEX64_RE.fullmatch(
            previous_hash
        ):
            raise ValueError(
                f"{what}.previous_hash must be a 64-character lowercase hex string"
            )
        record_hash = obj["hash"]
        if not isinstance(record_hash, str) or not _HEX64_RE.fullmatch(record_hash):
            raise ValueError(
                f"{what}.hash must be a 64-character lowercase hex string"
            )
        return {
            "id": event_id,
            "target": target.text,
            "kind": kind,
            "outcome": outcome,
            "occurred_ms": occurred_ms,
            "sequence": sequence,
            "previous_hash": previous_hash,
            "hash": record_hash,
        }

    @staticmethod
    def _verification_failure(
        checked: int, last_hash: str, index: int, reason: str
    ) -> dict[str, Any]:
        return {
            "verification": {
                "valid": False,
                "checked": checked,
                "head_hash": last_hash,
                "failure": {"index": index, "reason": reason},
            }
        }

    def analyze_web_security(self, payload: object) -> dict[str, Any]:
        """Analyze offline HTTP response observations for security issues.

        Pure, local evaluation: no network access and no persistent state.
        All structure is validated first (including duplicate observation and
        check entries); only then are observation targets checked against the
        allow/deny scope. Raises ValueError on malformed input and
        ScopeViolationError when any target is out of scope; never returns
        partial results. Only the requested check categories run, in request
        order, and the same input always produces the same findings.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        required = {"allow", "deny", "checks", "observations"}
        keys = set(payload)
        missing = required - keys
        if missing:
            raise ValueError(f"missing field: {sorted(missing)[0]}")
        extra = keys - required
        if extra:
            raise ValueError(f"unknown field: {sorted(extra)[0]}")

        allow_rules, deny_rules = self._parse_scope_rules(payload)

        raw_checks = payload["checks"]
        if not isinstance(raw_checks, list) or not raw_checks:
            raise ValueError("field checks must be a non-empty array")
        seen_checks: set[str] = set()
        checks: list[str] = []
        for check in raw_checks:
            if check not in WEB_SECURITY_CHECKS:
                raise ValueError(
                    f"checks must contain only values from {WEB_SECURITY_CHECKS}"
                )
            if check in seen_checks:
                raise ValueError(f"duplicate check entry: {check!r}")
            seen_checks.add(check)
            checks.append(check)

        raw_observations = payload["observations"]
        if not isinstance(raw_observations, list):
            raise ValueError("field observations must be an array")
        observations = [
            _parse_web_observation(raw, i)
            for i, raw in enumerate(raw_observations)
        ]
        self._require_unique_ids(
            (observation.id for observation in observations), "observation"
        )

        # Scope gate: every observation target must be authorized before any
        # analysis happens; a single rejection voids the whole request.
        self._assert_targets_in_scope(
            (observation.target for observation in observations),
            allow_rules,
            deny_rules,
        )

        findings: list[dict[str, Any]] = []
        for observation in observations:
            for check in checks:
                if check == "cors":
                    if self._cors_wildcard_credentials(observation.headers):
                        findings.append(
                            {
                                "observation_id": observation.id,
                                "target": observation.target.text,
                                "category": "cors_wildcard_credentials",
                                "severity": "high",
                                "cookie_name": None,
                            }
                        )
                elif check == "cookie":
                    findings.extend(self._cookie_findings(observation))
                else:
                    findings.extend(self._security_header_findings(observation))
        return {"findings": findings}

    @staticmethod
    def _header_values_ci(
        headers: dict[str, tuple[str, ...]], wanted: str
    ) -> list[str]:
        """All values for a header name, case-insensitively, in input order."""
        wanted = wanted.lower()
        values: list[str] = []
        for name, vals in headers.items():
            if name.lower() == wanted:
                values.extend(vals)
        return values

    @classmethod
    def _cors_wildcard_credentials(
        cls, headers: dict[str, tuple[str, ...]]
    ) -> bool:
        """Wildcard ACAO combined with credential-enabled responses."""
        wildcard_origin = any(
            "*" in value
            for value in cls._header_values_ci(
                headers, "access-control-allow-origin"
            )
        )
        credentials_true = any(
            "true" in value.lower()
            for value in cls._header_values_ci(
                headers, "access-control-allow-credentials"
            )
        )
        return wildcard_origin and credentials_true

    @staticmethod
    def _cookie_attributes(value: str) -> frozenset[str]:
        """Lowercased attribute names of one Set-Cookie value."""
        attrs: set[str] = set()
        pieces = value.split(";")
        for piece in pieces[1:]:
            name = piece.split("=", 1)[0].strip().lower()
            if name:
                attrs.add(name)
        return frozenset(attrs)

    @classmethod
    def _cookie_findings(
        cls, observation: _WebObservation
    ) -> list[dict[str, Any]]:
        """Per-Set-Cookie Secure/HttpOnly findings in fixed order."""
        findings: list[dict[str, Any]] = []
        for value in cls._header_values_ci(observation.headers, "set-cookie"):
            cookie_name = value.split("=", 1)[0]
            attrs = cls._cookie_attributes(value)
            # Secure is only meaningful on HTTPS responses; HttpOnly is
            # checked on every scheme. A cookie missing both yields two
            # findings in the fixed Secure-then-HttpOnly order.
            categories: list[str] = []
            if observation.scheme == "https" and "secure" not in attrs:
                categories.append("cookie_missing_secure")
            if "httponly" not in attrs:
                categories.append("cookie_missing_httponly")
            findings.extend(
                {
                    "observation_id": observation.id,
                    "target": observation.target.text,
                    "category": category,
                    "severity": "medium",
                    "cookie_name": cookie_name,
                }
                for category in categories
            )
        return findings

    @classmethod
    def _security_header_findings(
        cls, observation: _WebObservation
    ) -> list[dict[str, Any]]:
        """HSTS, CSP, clickjacking and MIME-sniffing findings, fixed order.

        Every value of a repeated header participates; malformed header
        values merely fail their check and never make the request fail.
        HSTS is evaluated for https observations only.
        """
        headers = observation.headers
        missing = {
            "hsts_missing_or_invalid": (
                observation.scheme == "https" and not cls._hsts_effective(headers)
            ),
            "csp_missing": not cls._csp_present(headers),
            "clickjacking_unprotected": not (
                cls._xfo_protects(headers)
                or cls._frame_ancestors_protects(headers)
            ),
            "nosniff_missing": not cls._nosniff_present(headers),
        }
        return [
            {
                "observation_id": observation.id,
                "target": observation.target.text,
                "category": category,
                "severity": severity,
                "cookie_name": None,
            }
            for category, severity in _SECURITY_HEADER_FINDING_ORDER
            if missing[category]
        ]

    @staticmethod
    def _hsts_effective(headers: dict[str, tuple[str, ...]]) -> bool:
        """Whether any Strict-Transport-Security value enables HSTS.

        The value is split on semicolons; a directive named max-age
        (case-insensitive, whitespace-trimmed) is effective only when the
        text right of '=' consists solely of ASCII decimal digits, at least
        one of them non-zero. Anything else, including missing '=' or
        surrounding whitespace on the age, is treated as malformed. The
        numeric test is purely lexical so even an oversized digit run cannot
        raise.
        """
        for value in Service._header_values_ci(
            headers, "strict-transport-security"
        ):
            for directive in value.split(";"):
                name, sep, raw_age = directive.partition("=")
                if not sep or name.strip().lower() != "max-age":
                    continue
                if (
                    raw_age
                    and all(char in _ASCII_DIGITS for char in raw_age)
                    and any(char != "0" for char in raw_age)
                ):
                    return True
        return False

    @staticmethod
    def _csp_present(headers: dict[str, tuple[str, ...]]) -> bool:
        """Whether any Content-Security-Policy value is non-empty when trimmed."""
        return any(
            bool(value.strip())
            for value in Service._header_values_ci(
                headers, "content-security-policy"
            )
        )

    @staticmethod
    def _xfo_protects(headers: dict[str, tuple[str, ...]]) -> bool:
        """Whether any X-Frame-Options value is DENY or SAMEORIGIN."""
        return any(
            value.strip().upper() in ("DENY", "SAMEORIGIN")
            for value in Service._header_values_ci(headers, "x-frame-options")
        )

    @staticmethod
    def _frame_ancestors_protects(headers: dict[str, tuple[str, ...]]) -> bool:
        """Whether any CSP value carries frame-ancestors with a non-empty arg.

        Directives are split on semicolons; the directive name is the first
        whitespace-delimited token (case-insensitive) and anything after it
        must contain a non-whitespace character. Report-Only policies are not
        considered.
        """
        for value in Service._header_values_ci(
            headers, "content-security-policy"
        ):
            for directive in value.split(";"):
                pieces = directive.split(None, 1)
                if (
                    pieces
                    and pieces[0].lower() == "frame-ancestors"
                    and len(pieces) == 2
                    and pieces[1].strip()
                ):
                    return True
        return False

    @staticmethod
    def _nosniff_present(headers: dict[str, tuple[str, ...]]) -> bool:
        """Whether any X-Content-Type-Options value is exactly nosniff."""
        return any(
            value.strip().lower() == "nosniff"
            for value in Service._header_values_ci(
                headers, "x-content-type-options"
            )
        )
