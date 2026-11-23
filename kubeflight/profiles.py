# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Policy profiles: data-driven presets that choose which findings count and at what severity.

A profile never changes what KubeFlight detects; it changes what is reported, scored and gated.
Findings that are critical before the profile is applied can be raised but never disabled or lowered.
"""
from __future__ import annotations
import fnmatch
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
import yaml
from .models import Finding
from .registry import REGISTRY, SEVERITIES, SEVERITY_RANK

PROFILE_DIR = Path(__file__).with_name("profiles")
MAX_FILE_BYTES = 128 * 1024
MAX_PATTERNS = 500
MAX_EXTENDS_DEPTH = 4
FAIL_ON = ("never", "low", "medium", "high", "critical")
_KEYS = {"name", "description", "extends", "min_severity", "fail_on", "severity", "enable", "disable"}


@dataclass(frozen=True)
class Layer:
    name: str
    severity: tuple[tuple[str, str], ...] = ()
    enable: tuple[str, ...] = ()
    disable: tuple[str, ...] = ()
    min_severity: str | None = None
    fail_on: str | None = None


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    layers: tuple[Layer, ...] = field(default_factory=tuple)
    source: str = "builtin"

    @property
    def fail_on(self) -> str | None:
        return next((l.fail_on for l in reversed(self.layers) if l.fail_on), None)

    @property
    def min_severity(self) -> str:
        return next((l.min_severity for l in reversed(self.layers) if l.min_severity), "info")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "source": self.source, "min_severity": self.min_severity, "fail_on": self.fail_on,
                "layers": [{"name": l.name, "severity": dict(l.severity), "enable": list(l.enable), "disable": list(l.disable),
                            "min_severity": l.min_severity, "fail_on": l.fail_on} for l in self.layers]}


def _match(patterns, fid: str) -> bool:
    return any(fnmatch.fnmatchcase(fid, p) for p in patterns)


def referenced_patterns(profile: Profile) -> set[str]:
    out: set[str] = set()
    for l in profile.layers:
        out |= {p for p, _ in l.severity} | set(l.enable) | set(l.disable)
    return out


def _check_patterns(pats: list[str], where: str) -> None:
    for p in pats:
        if p.startswith("KF-CUS-"):
            continue  # user-defined custom rule ids are not in the registry
        if not any(fnmatch.fnmatchcase(i, p) for i in REGISTRY):
            raise ValueError(f"{where}: {p!r} matches no known finding id (see `kubeflight explain --list`)")


def _str_list(v: Any, key: str, where: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or len(v) > MAX_PATTERNS or not all(isinstance(x, str) and x.strip() and len(x) <= 40 for x in v):
        raise ValueError(f"{where}: '{key}' must be a list of up to {MAX_PATTERNS} finding ids or patterns such as KF-NET-*")
    out = [x.strip().upper() for x in v]
    _check_patterns(out, where)
    return out


def _is_pattern(p: str) -> bool:
    return any(c in p for c in "*?[")


def _layer(data: dict[str, Any], where: str) -> Layer:
    unknown = set(data) - _KEYS
    if unknown:
        raise ValueError(f"{where}: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    sev = data.get("severity")
    sev = {} if sev is None else sev
    if not isinstance(sev, dict) or len(sev) > MAX_PATTERNS:
        raise ValueError(f"{where}: 'severity' must be a mapping of finding id (or pattern) to severity")
    pairs = []
    for k, v in sev.items():
        if not isinstance(k, str) or v not in SEVERITIES:
            raise ValueError(f"{where}: severity for {str(k)[:40]!r} must be one of {', '.join(SEVERITIES)}")
        pairs.append((k.strip().upper(), v))
    _check_patterns([p for p, _ in pairs], where)
    pairs.sort(key=lambda kv: not _is_pattern(kv[0]))  # wildcards first, so exact ids (applied last) win
    ms = data.get("min_severity")
    if ms is not None and ms not in SEVERITIES:
        raise ValueError(f"{where}: min_severity must be one of {', '.join(SEVERITIES)}")
    fo = data.get("fail_on")
    if fo is not None and fo not in FAIL_ON:
        raise ValueError(f"{where}: fail_on must be one of {', '.join(FAIL_ON)}")
    return Layer(str(data.get("name") or where), tuple(pairs), tuple(_str_list(data.get("enable"), "enable", where)),
                 tuple(_str_list(data.get("disable"), "disable", where)), ms, fo)


def parse_profile(data: Any, source: str = "inline", _depth: int = 0, default_extends: str | None = None) -> Profile:
    if not isinstance(data, dict):
        raise ValueError(f"profile {source} must be a mapping")
    if _depth > MAX_EXTENDS_DEPTH:
        raise ValueError(f"profile {source}: 'extends' chain is too deep or circular")
    name = data.get("name")
    if name is not None and (not isinstance(name, str) or not name.strip() or len(name) > 60):
        raise ValueError(f"profile {source}: name must be a short string")
    layer = _layer(data, f"profile {name or source}")
    parent_name = data.get("extends", default_extends)
    layers: tuple[Layer, ...] = ()
    if parent_name is not None:
        if not isinstance(parent_name, str):
            raise ValueError(f"profile {name or source}: 'extends' must be a built-in profile name")
        layers = builtin_profile(parent_name, _depth + 1).layers
    return Profile(str(name or source), str(data.get("description") or "")[:300], layers + (layer,), source)


def builtin_names() -> list[str]:
    return sorted(p.stem for p in PROFILE_DIR.glob("*.yaml"))


def builtin_profile(name: str, _depth: int = 0) -> Profile:
    if not isinstance(name, str) or name not in builtin_names():
        raise ValueError(f"unknown profile {str(name)[:40]!r}; built-in profiles: {', '.join(builtin_names())}")
    data = yaml.safe_load((PROFILE_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
    return parse_profile(data, name, _depth)


def load_profile(name: str | None = None, file: str | Path | None = None) -> Profile | None:
    """``name`` selects a built-in; ``file`` loads a user profile (layered on top of ``name`` when both are given)."""
    if file is None:
        return builtin_profile(name) if name else None
    p = Path(file)
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("profile file is too large")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ValueError(f"invalid profile file: {e}") from e
    return parse_profile(data, p.stem, default_extends=name)


def apply_profile(findings: list[Finding], profile: Profile | None) -> tuple[list[Finding], dict[str, Any] | None]:
    if profile is None:
        return findings, None
    kept: list[Finding] = []
    dropped: dict[str, int] = {}
    adjusted: dict[str, str] = {}
    protected: set[str] = set()
    floor = SEVERITY_RANK[profile.min_severity]
    for f in findings:
        sev = f.severity
        for l in profile.layers:
            for pat, s in l.severity:
                if fnmatch.fnmatchcase(f.id, pat):
                    sev = s
        verdict = None
        for l in profile.layers:
            if _match(l.enable, f.id):
                verdict = True
            elif _match(l.disable, f.id):
                verdict = False
        if f.severity == "critical":
            if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK["critical"] or verdict is False:
                protected.add(f.id)
            sev = "critical" if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK["critical"] else sev
            if verdict is False:
                verdict = None
        if verdict is None:
            verdict = SEVERITY_RANK.get(sev, 0) >= floor
        if not verdict:
            dropped[f.id] = dropped.get(f.id, 0) + 1
            continue
        if sev != f.severity:
            adjusted[f.id] = f"{f.severity}->{sev}"
            f = replace(f, severity=sev)
        kept.append(f)
    return kept, {"name": profile.name, "source": profile.source, "min_severity": profile.min_severity,
                  "dropped": dict(sorted(dropped.items())), "adjusted": dict(sorted(adjusted.items())), "protected_critical": sorted(protected)}
