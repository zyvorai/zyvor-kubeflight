# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Glue for the optional-input checks: API removal table, field validation, custom rules, image hygiene, SBOM/advisories."""
from __future__ import annotations
import datetime as dt
from typing import Any
from .apis import api_findings
from .fields import field_findings
from .images import ImagePolicy, image_findings
from .models import Finding
from .rules import Rule, rule_findings
from .vulns import AdvisoryDB, Sbom, vulnerability_findings, LIMITATIONS as SUPPLY_LIMITATIONS

def plus_findings(resources: list[dict[str, Any]], *, target: str, rules: list[Rule] | None = None, field_check: bool = True,
                  image_policy: ImagePolicy | None = None, sboms: list[Sbom] | None = None, advisories: list[AdvisoryDB] | None = None,
                  today: dt.date | None = None) -> list[Finding]:
    if bool(sboms) != bool(advisories):
        raise ValueError("SBOM matching needs both --sbom and --advisories (an SBOM without advisories, or advisories without an SBOM, cannot produce results)")
    out = api_findings(resources, target)
    if field_check:
        out += field_findings(resources)
    if rules:
        out += rule_findings(resources, rules)
    out += image_findings(resources, image_policy)
    if sboms and advisories:
        out += vulnerability_findings(resources, sboms, advisories, today)
    return out

def supply_limitations(sboms: list[Sbom] | None, advisories: list[AdvisoryDB] | None) -> list[str]:
    return list(SUPPLY_LIMITATIONS) if sboms and advisories else []
