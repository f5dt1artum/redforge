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

MAX_SCOPE_ITEMS = 1000
_MAX_HOSTNAME_LEN = 253
_MAX_LABEL_LEN = 63
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _normalize_hostname(raw: str) -> str:
    """Return the lowercase IDNA ASCII form without trailing dot, or ValueError."""
    candidate = raw[:-1] if raw.endswith(".") else raw
    if not candidate:
        raise ValueError(f"invalid hostname: {raw!r}")
    try:
        ascii_form = candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise ValueError(f"invalid hostname: {raw!r}") from None
    if not ascii_form or len(ascii_form) > _MAX_HOSTNAME_LEN:
        raise ValueError(f"invalid hostname: {raw!r}")
    for label in ascii_form.split("."):
        if not 1 <= len(label) <= _MAX_LABEL_LEN or _LABEL_RE.fullmatch(label) is None:
            raise ValueError(f"invalid hostname: {raw!r}")
    return ascii_form


@dataclass(frozen=True)
class _Entry:
    """A normalized rule or target.

    kind is one of "ip", "net", "host", "wild"; value is the parsed form
    (ipaddress object or hostname string); text is the normalized text.
    """

    kind: str
    value: Any
    text: str


def _parse_entry(raw: Any, *, allow_wildcard: bool) -> _Entry:
    if not isinstance(raw, str) or not raw:
        raise ValueError("scope entries must be non-empty strings")
    if raw.startswith("*"):
        if not (allow_wildcard and raw.startswith("*.")):
            raise ValueError(f"invalid wildcard entry: {raw!r}")
        suffix = _normalize_hostname(raw[2:])
        return _Entry("wild", suffix, f"*.{suffix}")
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        addr = None
    if addr is not None:
        return _Entry("ip", addr, str(addr))
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(f"invalid network: {raw!r}") from None
        return _Entry("net", net, str(net))
    host = _normalize_hostname(raw)
    return _Entry("host", host, host)


def _matches(rule: _Entry, target: _Entry) -> bool:
    """Whether a non-network target matches a rule."""
    if target.kind == "ip":
        if rule.kind == "ip":
            return rule.value == target.value
        if rule.kind == "net":
            return target.value in rule.value
        return False
    if target.kind == "host":
        if rule.kind == "host":
            return rule.value == target.value
        if rule.kind == "wild":
            return target.value != rule.value and target.value.endswith(f".{rule.value}")
        return False
    return False


def _decide(
    target: _Entry, allow_rules: list[_Entry], deny_rules: list[_Entry]
) -> tuple[bool, str, str | None]:
    """Return (allowed, reason, matched_rule). Deny rules win over allow rules."""
    if target.kind == "net":
        for rule in deny_rules:
            if (
                rule.kind == "net"
                and rule.value.version == target.value.version
                and target.value.overlaps(rule.value)
            ):
                return False, "deny_overlap", rule.text
        for rule in allow_rules:
            if rule.kind == "net" and target.value.subnet_of(rule.value):
                return True, "allowed", rule.text
        return False, "no_allow_match", None
    for rule in deny_rules:
        if _matches(rule, target):
            return False, "deny_match", rule.text
    for rule in allow_rules:
        if _matches(rule, target):
            return True, "allowed", rule.text
    return False, "no_allow_match", None


class Service:
    """Health reporting plus authorization scope evaluation."""

    name = "redforge"
    version = __version__

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def evaluate_scope(self, payload: Any) -> dict[str, Any]:
        """Evaluate targets against allow/deny scope rules.

        Pure function of the payload: performs no network access and writes
        no persistent state. Raises ValueError on any malformed input.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object")
        sections: dict[str, list[Any]] = {}
        for key in ("allow", "deny", "targets"):
            value = payload.get(key)
            if not isinstance(value, list):
                raise ValueError(f"payload field {key!r} must be an array")
            if len(value) > MAX_SCOPE_ITEMS:
                raise ValueError(f"payload field {key!r} exceeds {MAX_SCOPE_ITEMS} entries")
            sections[key] = value
        if not sections["targets"]:
            raise ValueError("payload field 'targets' must not be empty")

        allow_rules = [_parse_entry(item, allow_wildcard=True) for item in sections["allow"]]
        deny_rules = [_parse_entry(item, allow_wildcard=True) for item in sections["deny"]]

        decisions = []
        for raw in sections["targets"]:
            target = _parse_entry(raw, allow_wildcard=False)
            allowed, reason, matched = _decide(target, allow_rules, deny_rules)
            decisions.append(
                {
                    "original": raw,
                    "normalized": target.text,
                    "allowed": allowed,
                    "reason": reason,
                    "matched_rule": matched,
                }
            )
        return {"decisions": decisions}
