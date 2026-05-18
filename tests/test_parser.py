"""Tests for the Terraform HCL parser."""

import pytest
from esga.parser.terraform import parse_tf_file, count_resources


VALID_TF = '''
resource "aws_s3_bucket" "mybucket" {
  bucket = "test-bucket"
  acl    = "private"
}

resource "azurerm_storage_account" "mystorage" {
  name                     = "teststorage"
  resource_group_name      = "rg-test"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
'''

EMPTY_TF = '''
variable "region" {
  default = "us-east-1"
}
'''


def test_parse_valid_tf():
    resources = parse_tf_file(VALID_TF)
    assert len(resources) == 2
    types = [r[0] for r in resources]
    assert "aws_s3_bucket" in types
    assert "azurerm_storage_account" in types


def test_parse_resource_names():
    resources = parse_tf_file(VALID_TF)
    names = [r[1] for r in resources]
    assert "mybucket" in names
    assert "mystorage" in names


def test_parse_attributes():
    resources = parse_tf_file(VALID_TF)
    bucket = next(r for r in resources if r[0] == "aws_s3_bucket")
    attrs = bucket[2]
    # python-hcl2 wraps values in lists
    assert "bucket" in attrs
    assert "acl" in attrs


def test_count_resources():
    assert count_resources(VALID_TF) == 2


def test_parse_no_resources():
    resources = parse_tf_file(EMPTY_TF)
    assert len(resources) == 0


def test_parse_empty_string():
    resources = parse_tf_file("")
    assert len(resources) == 0
