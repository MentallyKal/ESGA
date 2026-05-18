# vulnerable.tf — Intentionally insecure Terraform for testing.
# Expected: 8-10 findings across multiple severity levels.

resource "azurerm_storage_account" "bad_storage" {
  name                     = "badstorage2024"
  resource_group_name      = "rg-dev"
  location                 = "westus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # VIOLATION: Public blob access enabled (CRITICAL)
  allow_blob_public_access  = true

  # VIOLATION: HTTPS not enforced (HIGH)
  enable_https_traffic_only = false

  # VIOLATION: TLS version too low (MEDIUM)
  min_tls_version           = "TLS1_0"

  # VIOLATION: No customer_managed_key block (MEDIUM)
}

resource "azurerm_network_security_group" "bad_nsg" {
  name                = "bad-nsg"
  location            = "westus"
  resource_group_name = "rg-dev"

  # VIOLATION: SSH open to the entire internet (CRITICAL)
  security_rule {
    name                       = "AllowSSHFromAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
  }
}

resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-public-bucket"

  # VIOLATION: Public read ACL (CRITICAL)
  acl = "public-read"

  # VIOLATION: No server_side_encryption_configuration block (HIGH)
  # VIOLATION: No versioning enabled (LOW)
}

resource "aws_security_group" "bad_sg" {
  name        = "open-sg"
  description = "Wide open security group"
  vpc_id      = "vpc-654321"

  # VIOLATION: All ports open to the world, includes port 22 (CRITICAL)
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "bad_policy" {
  name        = "overly-permissive-policy"
  description = "Grants full access to everything"

  # VIOLATION: Wildcard action (CRITICAL)
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
