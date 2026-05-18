"""
Parse Terraform (.tf) files into structured Python dicts using python-hcl2.

python-hcl2 produces output like:
{
    "resource": [
        {
            "azurerm_storage_account": {
                "mystorage": {
                    "name": ["storageacctname"],
                    "allow_blob_public_access": [true],
                    ...
                }
            }
        },
        ...
    ]
}

This module normalizes that into a flat list of:
    (resource_type, resource_name, attributes_dict)
"""

import io
from typing import Any

import hcl2


def parse_tf_file(file_content: str) -> list[tuple[str, str, dict[str, Any]]]:
    """
    Parse a .tf file content string and extract all resource blocks.

    Args:
        file_content: The raw text content of a .tf file.

    Returns:
        List of tuples: (resource_type, resource_name, attributes_dict)
        Example: [("azurerm_storage_account", "mystorage", {...})]
    """
    parsed = hcl2.load(io.StringIO(file_content))
    resources: list[tuple[str, str, dict[str, Any]]] = []

    resource_blocks = parsed.get("resource", [])
    for block in resource_blocks:
        if not isinstance(block, dict):
            continue
        for resource_type, type_body in block.items():
            if not isinstance(type_body, dict):
                continue
            for resource_name, attrs in type_body.items():
                if isinstance(attrs, dict):
                    resources.append((resource_type, resource_name, attrs))

    return resources


def count_resources(file_content: str) -> int:
    """Count total resource blocks in a .tf file."""
    return len(parse_tf_file(file_content))
