"""
Rule engine: evaluates a parsed Terraform resource dict against security Rules.

The engine receives:
  - resource_type (str): e.g. "azurerm_storage_account"
  - resource_name (str): e.g. "mystorage"
  - attrs (dict): the attribute dictionary from python-hcl2
  - rules (list of Rule ORM objects): all enabled rules

Returns a list of finding dicts for any violations detected.
"""

from __future__ import annotations

import json
from typing import Any


def _unwrap(val: Any) -> Any:
    """Unwrap single-element lists (python-hcl2 wraps all values in lists)."""
    if isinstance(val, list) and len(val) == 1:
        return val[0]
    return val


def _get_nested_attr(attrs: dict, path: str) -> Any:
    """
    Traverse a dot-separated attribute path into a nested dict.
    Returns None if any key is missing.

    python-hcl2 wraps values in lists, so unwrap single-element lists at
    each level.
    """
    keys = path.split(".")
    current = attrs
    for key in keys:
        if isinstance(current, list):
            if len(current) > 0:
                current = current[0]
            else:
                return None
        if isinstance(current, dict):
            if key in current:
                current = current[key]
            else:
                return None
        else:
            return None
    # Unwrap final value
    if isinstance(current, list) and len(current) == 1:
        current = current[0]
    return current


# ── Condition checkers ──────────────────────────────────────────────


def _check_equals(actual: Any, expected_str: str) -> bool:
    """Check if actual value equals the expected value (parsed from string)."""
    if actual is None:
        return False
    expected = expected_str.strip().strip('"')
    if expected.lower() == "true":
        return actual is True or str(actual).lower() == "true"
    if expected.lower() == "false":
        return actual is False or str(actual).lower() == "false"
    return str(actual).lower() == expected.lower()


def _check_not_equals(actual: Any, expected_str: str) -> bool:
    """True if attribute is missing or does not match expected."""
    if actual is None:
        return True  # Missing counts as not matching
    return not _check_equals(actual, expected_str)


def _check_matches_any(actual: Any, expected_str: str) -> bool:
    """True if actual value is in the JSON list of expected values."""
    if actual is None:
        return False
    expected_list = json.loads(expected_str)
    return str(actual).lower() in [v.lower() for v in expected_list]


def _check_missing_block(attrs: dict, path: str) -> bool:
    """True if the named block/key is absent from the resource attributes."""
    val = _get_nested_attr(attrs, path)
    return val is None


# ── Custom handlers for complex resource structures ─────────────────


def _is_ssh_open_nsg_rule(r: dict) -> bool:
    """Check a single Azure NSG rule dict for SSH open to world."""
    direction = str(_unwrap(r.get("direction", ""))).lower()
    access = str(_unwrap(r.get("access", ""))).lower()
    dest_port = str(_unwrap(r.get("destination_port_range", "")))
    source = str(_unwrap(r.get("source_address_prefix", "")))
    return (
        direction == "inbound"
        and access == "allow"
        and dest_port in ("22", "*")
        and source in ("0.0.0.0/0", "*", "0.0.0.0")
    )


def _check_nsg_ssh_open(attrs: dict) -> bool:
    """Azure NSG: check if any security_rule allows port 22 from 0.0.0.0/0."""
    rules = attrs.get("security_rule", [])
    if not isinstance(rules, list):
        rules = [rules]
    for rule_block in rules:
        if isinstance(rule_block, list):
            for r in rule_block:
                if isinstance(r, dict) and _is_ssh_open_nsg_rule(r):
                    return True
        elif isinstance(rule_block, dict):
            if _is_ssh_open_nsg_rule(rule_block):
                return True
    return False


def _is_ssh_open_sg_ingress(b: dict) -> bool:
    """Check a single AWS SG ingress block for SSH open to world."""
    from_port = _unwrap(b.get("from_port", -1))
    to_port = _unwrap(b.get("to_port", -1))
    cidr_blocks = b.get("cidr_blocks", [])
    if isinstance(cidr_blocks, list) and len(cidr_blocks) > 0:
        if isinstance(cidr_blocks[0], list):
            cidr_blocks = cidr_blocks[0]
    try:
        from_p = int(from_port)
        to_p = int(to_port)
    except (ValueError, TypeError):
        return False
    return from_p <= 22 <= to_p and "0.0.0.0/0" in cidr_blocks


def _check_sg_ssh_open(attrs: dict) -> bool:
    """AWS SG: check if any ingress block allows port 22 from 0.0.0.0/0."""
    ingress_blocks = attrs.get("ingress", [])
    if not isinstance(ingress_blocks, list):
        ingress_blocks = [ingress_blocks]
    for block in ingress_blocks:
        if isinstance(block, list):
            for b in block:
                if isinstance(b, dict) and _is_ssh_open_sg_ingress(b):
                    return True
        elif isinstance(block, dict):
            if _is_ssh_open_sg_ingress(block):
                return True
    return False


def _check_iam_wildcard(attrs: dict) -> bool:
    """Check if an aws_iam_policy contains Action: '*'."""
    policy_str = _unwrap(attrs.get("policy", ""))
    if not isinstance(policy_str, str):
        return False
    if "*" not in policy_str:
        return False
    # Try structured JSON parse
    try:
        policy_doc = json.loads(policy_str)
        statements = policy_doc.get("Statement", [])
        for stmt in statements:
            actions = stmt.get("Action", [])
            if actions == "*" or (isinstance(actions, list) and "*" in actions):
                return True
    except (json.JSONDecodeError, AttributeError):
        pass
    # Fallback: raw string pattern
    if '"Action": "*"' in policy_str or '"Action":"*"' in policy_str:
        return True
    return False


# ── Main evaluation function ────────────────────────────────────────


def evaluate_resource(
    resource_type: str,
    resource_name: str,
    attrs: dict,
    rules: list,
    file_path: str | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate a single Terraform resource against all applicable rules.

    Args:
        resource_type: e.g. "azurerm_storage_account"
        resource_name: e.g. "mystorage"
        attrs: The attribute dict from python-hcl2
        rules: List of Rule ORM objects (from DB)
        file_path: optional filename for reporting

    Returns:
        List of finding dicts with keys:
        rule_db_id, resource_name, resource_type, severity, message, file_path
    """
    findings: list[dict[str, Any]] = []

    for rule in rules:
        if rule.resource_type != resource_type:
            continue
        if not rule.enabled:
            continue

        violated = False
        condition = rule.condition

        if condition == "equals":
            actual = _get_nested_attr(attrs, rule.attribute_path)
            violated = _check_equals(actual, rule.expected_value)

        elif condition == "not_equals":
            actual = _get_nested_attr(attrs, rule.attribute_path)
            violated = _check_not_equals(actual, rule.expected_value)

        elif condition == "matches_any":
            actual = _get_nested_attr(attrs, rule.attribute_path)
            violated = _check_matches_any(actual, rule.expected_value)

        elif condition == "missing_block":
            violated = _check_missing_block(attrs, rule.attribute_path)

        elif condition == "not_exists":
            val = _get_nested_attr(attrs, rule.attribute_path)
            violated = val is None

        elif condition == "nsg_ssh_open":
            violated = _check_nsg_ssh_open(attrs)

        elif condition == "sg_ssh_open":
            violated = _check_sg_ssh_open(attrs)

        elif condition == "iam_wildcard_action":
            violated = _check_iam_wildcard(attrs)

        if violated:
            full_name = f"{resource_type}.{resource_name}"
            findings.append(
                {
                    "rule_db_id": rule.id,
                    "resource_name": full_name,
                    "resource_type": resource_type,
                    "severity": rule.severity,
                    "message": f"[{rule.rule_id}] {rule.name}: {rule.description}",
                    "file_path": file_path,
                }
            )

    return findings
