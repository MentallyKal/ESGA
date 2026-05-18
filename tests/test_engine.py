"""Tests for the rule evaluation engine."""

from esga.rules.engine import evaluate_resource


class MockRule:
    """Minimal mock of a Rule ORM object for testing."""

    def __init__(self, **kwargs):
        self.id = kwargs.get("id", 1)
        self.rule_id = kwargs.get("rule_id", "TEST_RULE")
        self.name = kwargs.get("name", "Test Rule")
        self.description = kwargs.get("description", "A test rule")
        self.resource_type = kwargs.get("resource_type", "test_resource")
        self.severity = kwargs.get("severity", "HIGH")
        self.attribute_path = kwargs.get("attribute_path", "test_attr")
        self.condition = kwargs.get("condition", "equals")
        self.expected_value = kwargs.get("expected_value", "true")
        self.enabled = kwargs.get("enabled", True)


def test_equals_condition_match():
    rule = MockRule(
        resource_type="azurerm_storage_account",
        attribute_path="allow_blob_public_access",
        condition="equals",
        expected_value="true",
    )
    attrs = {"allow_blob_public_access": [True]}
    findings = evaluate_resource(
        "azurerm_storage_account", "test", attrs, [rule]
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_equals_condition_no_match():
    rule = MockRule(
        resource_type="azurerm_storage_account",
        attribute_path="allow_blob_public_access",
        condition="equals",
        expected_value="true",
    )
    attrs = {"allow_blob_public_access": [False]}
    findings = evaluate_resource(
        "azurerm_storage_account", "test", attrs, [rule]
    )
    assert len(findings) == 0


def test_not_equals_missing_attribute():
    rule = MockRule(
        resource_type="azurerm_storage_account",
        attribute_path="min_tls_version",
        condition="not_equals",
        expected_value='"TLS1_2"',
    )
    attrs = {}  # Attribute missing
    findings = evaluate_resource(
        "azurerm_storage_account", "test", attrs, [rule]
    )
    assert len(findings) == 1


def test_not_equals_wrong_value():
    rule = MockRule(
        resource_type="azurerm_storage_account",
        attribute_path="min_tls_version",
        condition="not_equals",
        expected_value='"TLS1_2"',
    )
    attrs = {"min_tls_version": ["TLS1_0"]}
    findings = evaluate_resource(
        "azurerm_storage_account", "test", attrs, [rule]
    )
    assert len(findings) == 1


def test_not_equals_correct_value():
    rule = MockRule(
        resource_type="azurerm_storage_account",
        attribute_path="min_tls_version",
        condition="not_equals",
        expected_value='"TLS1_2"',
    )
    attrs = {"min_tls_version": ["TLS1_2"]}
    findings = evaluate_resource(
        "azurerm_storage_account", "test", attrs, [rule]
    )
    assert len(findings) == 0


def test_matches_any_condition():
    rule = MockRule(
        resource_type="aws_s3_bucket",
        attribute_path="acl",
        condition="matches_any",
        expected_value='["public-read", "public-read-write"]',
    )
    attrs = {"acl": ["public-read"]}
    findings = evaluate_resource("aws_s3_bucket", "test", attrs, [rule])
    assert len(findings) == 1


def test_matches_any_no_match():
    rule = MockRule(
        resource_type="aws_s3_bucket",
        attribute_path="acl",
        condition="matches_any",
        expected_value='["public-read", "public-read-write"]',
    )
    attrs = {"acl": ["private"]}
    findings = evaluate_resource("aws_s3_bucket", "test", attrs, [rule])
    assert len(findings) == 0


def test_missing_block_condition():
    rule = MockRule(
        resource_type="aws_s3_bucket",
        attribute_path="server_side_encryption_configuration",
        condition="missing_block",
    )
    attrs = {"bucket": ["test"]}  # No encryption block
    findings = evaluate_resource("aws_s3_bucket", "test", attrs, [rule])
    assert len(findings) == 1


def test_missing_block_present():
    rule = MockRule(
        resource_type="aws_s3_bucket",
        attribute_path="server_side_encryption_configuration",
        condition="missing_block",
    )
    attrs = {"server_side_encryption_configuration": [{"rule": [{}]}]}
    findings = evaluate_resource("aws_s3_bucket", "test", attrs, [rule])
    assert len(findings) == 0


def test_nsg_ssh_open():
    rule = MockRule(
        resource_type="azurerm_network_security_group",
        attribute_path="security_rule",
        condition="nsg_ssh_open",
        expected_value=None,
        severity="CRITICAL",
    )
    attrs = {
        "security_rule": [
            {
                "name": ["AllowSSH"],
                "direction": ["Inbound"],
                "access": ["Allow"],
                "destination_port_range": ["22"],
                "source_address_prefix": ["0.0.0.0/0"],
            }
        ]
    }
    findings = evaluate_resource(
        "azurerm_network_security_group", "test", attrs, [rule]
    )
    assert len(findings) == 1


def test_nsg_ssh_not_open():
    rule = MockRule(
        resource_type="azurerm_network_security_group",
        attribute_path="security_rule",
        condition="nsg_ssh_open",
        expected_value=None,
    )
    attrs = {
        "security_rule": [
            {
                "name": ["AllowSSH"],
                "direction": ["Inbound"],
                "access": ["Allow"],
                "destination_port_range": ["22"],
                "source_address_prefix": ["10.0.0.0/8"],
            }
        ]
    }
    findings = evaluate_resource(
        "azurerm_network_security_group", "test", attrs, [rule]
    )
    assert len(findings) == 0


def test_sg_ssh_open():
    rule = MockRule(
        resource_type="aws_security_group",
        attribute_path="ingress",
        condition="sg_ssh_open",
        expected_value=None,
        severity="CRITICAL",
    )
    attrs = {
        "ingress": [
            {
                "from_port": [0],
                "to_port": [65535],
                "cidr_blocks": [["0.0.0.0/0"]],
            }
        ]
    }
    findings = evaluate_resource("aws_security_group", "test", attrs, [rule])
    assert len(findings) == 1


def test_iam_wildcard():
    rule = MockRule(
        resource_type="aws_iam_policy",
        attribute_path="policy",
        condition="iam_wildcard_action",
        expected_value=None,
        severity="CRITICAL",
    )
    policy_json = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    attrs = {"policy": [policy_json]}
    findings = evaluate_resource("aws_iam_policy", "test", attrs, [rule])
    assert len(findings) == 1


def test_disabled_rule_skipped():
    rule = MockRule(
        resource_type="aws_s3_bucket",
        attribute_path="acl",
        condition="matches_any",
        expected_value='["public-read"]',
        enabled=False,
    )
    attrs = {"acl": ["public-read"]}
    findings = evaluate_resource("aws_s3_bucket", "test", attrs, [rule])
    assert len(findings) == 0


def test_wrong_resource_type_skipped():
    rule = MockRule(
        resource_type="aws_s3_bucket",
        attribute_path="acl",
        condition="matches_any",
        expected_value='["public-read"]',
    )
    attrs = {"acl": ["public-read"]}
    findings = evaluate_resource("aws_ec2_instance", "test", attrs, [rule])
    assert len(findings) == 0
