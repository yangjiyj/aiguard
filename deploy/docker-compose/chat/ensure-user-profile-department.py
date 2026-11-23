#!/usr/bin/env python3
"""Append the department attribute to a Keycloak UPConfig without dropping existing fields."""

import json
import sys


config = json.load(sys.stdin)
attributes = config.get("attributes")
if not isinstance(attributes, list):
    attributes = []

if not any(isinstance(item, dict) and item.get("name") == "department" for item in attributes):
    attributes.append(
        {
            "name": "department",
            "displayName": "${department}",
            "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]},
            "multivalued": False,
        }
    )

config["attributes"] = attributes
config.setdefault("groups", [])
json.dump(config, sys.stdout, separators=(",", ":"))
