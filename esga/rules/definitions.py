"""
Security rule definitions for the ESGA scanner.

Each rule is a dict with:
  - rule_id: Unique string identifier
  - name: Human-readable short name
  - description: Detailed explanation of the risk
  - resource_type: Terraform resource type to match
  - severity: CRITICAL | HIGH | MEDIUM | LOW
  - attribute_path: Dot-delimited path into the resource attributes
  - condition: How to evaluate the attribute
      "equals"           -> attribute value == expected_value
      "not_equals"       -> attribute value != expected_value (or missing)
      "matches_any"      -> attribute value in JSON list of expected_value
      "missing_block"    -> a nested block is absent entirely
      "nsg_ssh_open"     -> Azure NSG: security_rule allows SSH from 0.0.0.0/0
      "sg_ssh_open"      -> AWS SG: ingress allows SSH from 0.0.0.0/0
      "iam_wildcard_action" -> IAM policy contains Action: "*"
  - expected_value: The value to compare (JSON-encoded string, or None)
"""

SECURITY_RULES: list[dict] = [
    # 1 — Azure Storage Account: Public Blob Access Enabled
    {
        "rule_id": "AZURE_STORAGE_PUBLIC_ACCESS",
        "name": "Azure Storage Public Blob Access",
        "description": (
            "The azurerm_storage_account has allow_blob_public_access set to true. "
            "Public blob access exposes data to the internet without authentication."
        ),
        "resource_type": "azurerm_storage_account",
        "severity": "CRITICAL",
        "attribute_path": "allow_blob_public_access",
        "condition": "equals",
        "expected_value": "true",
    },
    # 2 — Azure NSG: SSH Open to World
    {
        "rule_id": "AZURE_NSG_SSH_OPEN",
        "name": "Azure NSG SSH Open to 0.0.0.0/0",
        "description": (
            "An azurerm_network_security_group security_rule allows inbound SSH "
            "(port 22) from any source (0.0.0.0/0 or *). This exposes VMs to "
            "brute-force and credential-stuffing attacks."
        ),
        "resource_type": "azurerm_network_security_group",
        "severity": "CRITICAL",
        "attribute_path": "security_rule",
        "condition": "nsg_ssh_open",
        "expected_value": None,
    },
    # 3 — AWS S3 Bucket: Public ACL
    {
        "rule_id": "AWS_S3_PUBLIC_ACL",
        "name": "AWS S3 Bucket Public ACL",
        "description": (
            "The aws_s3_bucket has an acl set to 'public-read', "
            "'public-read-write', or 'authenticated-read', making bucket "
            "contents accessible to unauthorized parties."
        ),
        "resource_type": "aws_s3_bucket",
        "severity": "CRITICAL",
        "attribute_path": "acl",
        "condition": "matches_any",
        "expected_value": '["public-read", "public-read-write", "authenticated-read"]',
    },
    # 4 — AWS Security Group: SSH Open to World
    {
        "rule_id": "AWS_SG_SSH_OPEN",
        "name": "AWS Security Group SSH Open to 0.0.0.0/0",
        "description": (
            "An aws_security_group allows inbound SSH (port 22) from 0.0.0.0/0, "
            "exposing instances to unauthorized remote access."
        ),
        "resource_type": "aws_security_group",
        "severity": "CRITICAL",
        "attribute_path": "ingress",
        "condition": "sg_ssh_open",
        "expected_value": None,
    },
    # 5 — Azure Storage: HTTPS Not Enforced
    {
        "rule_id": "AZURE_STORAGE_NO_HTTPS",
        "name": "Azure Storage HTTPS Not Enforced",
        "description": (
            "The azurerm_storage_account has enable_https_traffic_only set to false. "
            "Traffic without HTTPS can be intercepted via man-in-the-middle attacks."
        ),
        "resource_type": "azurerm_storage_account",
        "severity": "HIGH",
        "attribute_path": "enable_https_traffic_only",
        "condition": "equals",
        "expected_value": "false",
    },
    # 6 — Azure Storage: Missing Customer-Managed Encryption
    {
        "rule_id": "AZURE_STORAGE_NO_ENCRYPTION",
        "name": "Azure Storage Missing Customer-Managed Encryption",
        "description": (
            "The azurerm_storage_account is missing a customer_managed_key block, "
            "indicating encryption at rest is not configured with customer-managed keys."
        ),
        "resource_type": "azurerm_storage_account",
        "severity": "MEDIUM",
        "attribute_path": "customer_managed_key",
        "condition": "missing_block",
        "expected_value": None,
    },
    # 7 — AWS S3: Missing Server-Side Encryption
    {
        "rule_id": "AWS_S3_NO_ENCRYPTION",
        "name": "AWS S3 Missing Server-Side Encryption",
        "description": (
            "The aws_s3_bucket is missing a server_side_encryption_configuration "
            "block, meaning data at rest may not be encrypted."
        ),
        "resource_type": "aws_s3_bucket",
        "severity": "HIGH",
        "attribute_path": "server_side_encryption_configuration",
        "condition": "missing_block",
        "expected_value": None,
    },
    # 8 — AWS IAM Policy: Overly Permissive (wildcard actions)
    {
        "rule_id": "AWS_IAM_OVERLY_PERMISSIVE",
        "name": "AWS IAM Policy Overly Permissive",
        "description": (
            "An aws_iam_policy contains a statement with Action set to '*', "
            "granting unrestricted access to all AWS services and actions."
        ),
        "resource_type": "aws_iam_policy",
        "severity": "CRITICAL",
        "attribute_path": "policy",
        "condition": "iam_wildcard_action",
        "expected_value": None,
    },
    # 9 — Azure Storage: Minimum TLS Version Below 1.2
    {
        "rule_id": "AZURE_STORAGE_LOW_TLS",
        "name": "Azure Storage Minimum TLS Version Below 1.2",
        "description": (
            "The azurerm_storage_account does not enforce TLS 1.2 as the minimum "
            "version, leaving connections vulnerable to downgrade attacks."
        ),
        "resource_type": "azurerm_storage_account",
        "severity": "MEDIUM",
        "attribute_path": "min_tls_version",
        "condition": "not_equals",
        "expected_value": '"TLS1_2"',
    },
    # 10 — AWS S3: Versioning Not Enabled
    {
        "rule_id": "AWS_S3_NO_VERSIONING",
        "name": "AWS S3 Versioning Not Enabled",
        "description": (
            "The aws_s3_bucket does not have versioning enabled. Without versioning, "
            "accidental deletions or overwrites cannot be recovered."
        ),
        "resource_type": "aws_s3_bucket",
        "severity": "LOW",
        "attribute_path": "versioning.enabled",
        "condition": "not_equals",
        "expected_value": "true",
    },
]
