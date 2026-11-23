# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Glue for the optional-input checks: API removal table, field validation, custom rules."""
from __future__ import annotations
from typing import Any
from .apis import api_findings
from .fields import field_findings
from .models import Finding
from .rules import Rule, rule_findings

def plus_findings(resources: list[dict[str, Any]], *, target: str, rules: list[Rule] | None = None, field_check: bool = True) -> list[Finding]:
    out = api_findings(resources, target)
    if field_check:
        out += field_findings(resources)
    if rules:
        out += rule_findings(resources, rules)
    return out
