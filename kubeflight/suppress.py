# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Reviewed, expiring suppressions for known findings."""
from __future__ import annotations
import datetime as dt
import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import yaml
from .models import Finding

MAX_FILE_BYTES = 256 * 1024

@dataclass(frozen=True)
class Suppression:
    id: str
    resource: str
    reason: str
    expires: dt.date | None = None

    def expired(self, today: dt.date) -> bool:
        return self.expires is not None and self.expires < today

    def matches(self, f: Finding) -> bool:
        return f.id == self.id and fnmatch.fnmatchcase(f.resource, self.resource)

def parse_suppressions(data: Any) -> list[Suppression]:
    """Validate a parsed ignore document: {ignore: [{id, resource?, reason, expires?}]}."""
    if data is None:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("ignore", []), list):
        raise ValueError("ignore file must be a mapping with an 'ignore' list")
    out = []
    for i, e in enumerate(data.get("ignore", [])):
        if not isinstance(e, dict):
            raise ValueError(f"ignore[{i}] must be a mapping")
        fid = e.get("id")
        reason = str(e.get("reason") or "").strip()
        if not isinstance(fid, str) or not fid.startswith("KF-"):
            raise ValueError(f"ignore[{i}].id must be a finding id such as KF-EXP-001")
        if not reason:
            raise ValueError(f"ignore[{i}] ({fid}) needs a reason")
        exp = e.get("expires")
        if exp is not None and not isinstance(exp, dt.date):
            try:
                exp = dt.date.fromisoformat(str(exp))
            except ValueError as ex:
                raise ValueError(f"ignore[{i}].expires must be YYYY-MM-DD") from ex
        if isinstance(exp, dt.datetime):
            exp = exp.date()
        out.append(Suppression(fid, str(e.get("resource") or "*"), reason, exp))
    return out

def load_suppressions(path: str | Path) -> list[Suppression]:
    p = Path(path)
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("ignore file is too large")
    try:
        return parse_suppressions(yaml.safe_load(p.read_text(encoding="utf-8")))
    except yaml.YAMLError as e:
        raise ValueError(f"invalid ignore file: {e}") from e

def apply_suppressions(findings: list[Finding], sups: list[Suppression], today: dt.date | None = None):
    """Return (kept, suppressed, expired_findings). Critical findings can be suppressed
    only with an expiry date, so a permanent blind spot cannot hide a blocker."""
    today = today or dt.date.today()
    kept, suppressed, notes = [], [], []
    for f in findings:
        hit = next((s for s in sups if s.matches(f)), None)
        if hit is None:
            kept.append(f); continue
        if hit.expired(today):
            kept.append(f)
            notes.append(Finding("KF-SUP-900", "low", "suppression", "Suppression has expired", f.resource,
                                 f"{hit.id} expired {hit.expires.isoformat()}: {hit.reason}",
                                 "Fix the finding or renew the suppression with a new review."))
        elif f.severity == "critical" and hit.expires is None:
            kept.append(f)
            notes.append(Finding("KF-SUP-901", "low", "suppression", "Critical findings need an expiry to be suppressed", f.resource,
                                 f"{hit.id} suppression has no 'expires' date", "Add an expires date (YYYY-MM-DD)."))
        else:
            suppressed.append({"id": f.id, "resource": f.resource, "severity": f.severity, "reason": hit.reason,
                               "expires": hit.expires.isoformat() if hit.expires else None})
    return kept, suppressed, notes
