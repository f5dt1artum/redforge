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
