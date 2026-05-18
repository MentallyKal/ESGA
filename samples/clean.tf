# clean.tf — A secure Terraform configuration with no violations.

resource "azurerm_storage_account" "secure_storage" {
  name                     = "securestorage2024"
  resource_group_name      = "rg-production"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"

  allow_blob_public_access  = false
  enable_https_traffic_only = true
  min_tls_version           = "TLS1_2"

  customer_managed_key {
    key_vault_key_id          = "/subscriptions/xxx/keys/mykey"
    user_assigned_identity_id = "/subscriptions/xxx/identities/myid"
  }
}

resource "azurerm_network_security_group" "secure_nsg" {
  name                = "secure-nsg"
  location            = "eastus"
  resource_group_name = "rg-production"

  security_rule {
    name                       = "AllowSSHFromVPN"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }
}

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Secure security group"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
