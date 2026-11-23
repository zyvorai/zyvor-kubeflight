# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Offline SBOM + advisory matching.

This is NOT a vulnerability scanner. It never inspects images, never contacts a registry or a
vulnerability database, and only knows what the two user-supplied files say. See ``LIMITATIONS``.
"""
from __future__ import annotations
import datetime as dt
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote
import yaml
from .images import ImageRef, parse_image, workload_images, _sanitize
from .models import Finding

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_COMPONENTS = 50_000
MAX_ADVISORIES = 100_000
MAX_DEPTH = 8
MAX_VUL_FINDINGS = 500
SEVERITIES = ("critical", "high", "medium", "low", "info")

LIMITATIONS = [
    "Supply-chain matching is not a vulnerability scanner: it only compares the SBOM and advisory files you supply, offline. It does not inspect image contents, resolve tags or digests, or fetch advisories.",
    "A component with no matching advisory is not 'clean': the advisory file may be incomplete or stale, and version comparison is a tolerant approximation of each ecosystem's rules.",
    "An SBOM is matched to a workload by image repository (and tag/digest when both are known); an SBOM for a different build of the same repository can be applied to the wrong tag.",
]

_ECO_ALIASES = {"go": "golang", "rubygems": "gem", "crates.io": "cargo", "packagist": "composer", "debian": "deb", "ubuntu": "deb",
                "alpine": "apk", "pip": "pypi", "python": "pypi"}


def _eco(e: Any) -> str | None:
    if not isinstance(e, str) or not e.strip():
        return None
    e = e.strip().lower().split(":", 1)[0]
    return _ECO_ALIASES.get(e, e)


def _norm_name(name: str, eco: str | None) -> str:
    n = name.strip().lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def _read_bounded(path: str | Path, what: str) -> str:
    p = Path(path)
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{what} {p.name} is larger than {MAX_FILE_BYTES // 1024 // 1024} MiB")
    return p.read_text(encoding="utf-8")


def _load_doc(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except RecursionError as e:
        raise ValueError(f"{what} is nested too deeply") from e
    except ValueError:
        pass
    try:
        return yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as e:
        raise ValueError(f"{what} is not valid JSON or YAML: {_sanitize(e)}") from e


# --------------------------------------------------------------------------- versions

_PRE = {"a", "alpha", "b", "beta", "rc", "pre", "preview", "dev", "snapshot", "m", "milestone", "c"}


def _tokens(v: str) -> list[tuple[int, Any]]:
    v = v.strip().lower()
    v = re.sub(r"^v(?=\d)", "", v)
    v = re.sub(r"^\d+:", "", v)  # epoch
    out: list[tuple[int, Any]] = []
    for t in re.findall(r"\d+|[a-z]+", v):
        if t.isdigit():
            out.append((1, int(t)))
        else:
            out.append((0 if t in _PRE else 2, t))
    return out


def compare_versions(a: str, b: str) -> int:
    """Tolerant ordering for semver, PEP 440-ish, Debian-ish and plain dotted versions. Pre-release words sort low."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x == y:
            continue
        if x is None and y is not None:
            return 1 if y[0] == 0 else -1  # a is shorter: b is a pre-release (a is newer) or a later release
        if y is None and x is not None:
            return -1 if x[0] == 0 else 1
        if x is None or y is None:
            return 0
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        return -1 if x[1] < y[1] else 1
    return 0


_CONSTRAINT = re.compile(r"^\s*(<=|>=|==|!=|<|>|=)?\s*([^\s<>=!,]+)\s*$")


def parse_constraints(spec: str) -> list[tuple[str, str]]:
    if not isinstance(spec, str) or not spec.strip() or len(spec) > 200:
        raise ValueError(f"invalid version range {_sanitize(spec, 60)!r}")
    if spec.strip() == "*":
        return []
    out = []
    for part in spec.split(","):
        m = _CONSTRAINT.match(part)
        if not m:
            raise ValueError(f"invalid version range {_sanitize(spec, 60)!r}")
        op = m.group(1) or "="
        out.append(("=" if op == "==" else op, m.group(2)))
    return out


def clause_matches(clause: list[tuple[str, str]], version: str) -> bool:
    for op, v in clause:
        c = compare_versions(version, v)
        if not {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0, "!=": c != 0}[op]:
            return False
    return True


def _describe(clauses: list[list[tuple[str, str]]], versions: set[str]) -> str:
    parts = [(" ".join(f"{o}{v}" for o, v in c) or "*") for c in clauses]
    if versions:
        parts.append("versions: " + ", ".join(sorted(versions)[:5]) + ("..." if len(versions) > 5 else ""))
    return "; ".join(parts) or "(no ranges)"


# --------------------------------------------------------------------------- CVSS v3

_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44}, "UI": {"N": .85, "R": .62},
      "C": {"H": .56, "L": .22, "N": 0.0}, "I": {"H": .56, "L": .22, "N": 0.0}, "A": {"H": .56, "L": .22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Base score for a CVSS:3.0/3.1 vector, or None if it is not a valid v3 vector."""
    if not isinstance(vector, str) or not re.match(r"^CVSS:3\.[01]/", vector):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = {"U": False, "C": True}[m["S"]]
        pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if scope_changed else 1.0) * (impact + expl), 10))


def _bucket(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"


def _sev_word(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    w = v.strip().lower()
    return {"moderate": "medium", "important": "high", "negligible": "low", "none": "info", "unknown": None}.get(w, w if w in SEVERITIES else None)


# --------------------------------------------------------------------------- advisories

@dataclass(frozen=True)
class Affected:
    names: tuple[str, ...]
    ecosystem: str | None
    clauses: tuple[tuple[tuple[str, str], ...], ...]
    versions: frozenset[str]
    fixed: tuple[str, ...] = ()

    def matches_version(self, version: str) -> bool:
        if version in self.versions:
            return True
        return any(clause_matches(list(c), version) for c in self.clauses)


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    severity_source: str
    affected: tuple[Affected, ...]
    url: str = ""


@dataclass
class AdvisoryDB:
    source: str
    fmt: str
    version: str | None
    expires: dt.date | None
    advisories: list[Advisory] = field(default_factory=list)

    def expired(self, today: dt.date) -> bool:
        return self.expires is not None and self.expires < today


def _date(v: Any, key: str) -> dt.date | None:
    if v is None:
        return None
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v)[:10])
    except ValueError as e:
        raise ValueError(f"advisory file '{key}' must be YYYY-MM-DD") from e


def _purl_parts(purl: str) -> tuple[str | None, str | None, str | None]:
    """(type, namespace/name, version) from a package URL; tolerant of qualifiers/subpaths."""
    m = re.match(r"^pkg:([A-Za-z0-9.+-]+)/([^?#]+)", purl or "")
    if not m:
        return None, None, None
    path = m.group(2)
    ver = None
    if "@" in path:
        path, ver = path.rsplit("@", 1)
    return m.group(1).lower(), unquote(path), unquote(ver) if ver else None


def _names_for(name: str | None, group: str | None, purl: str | None) -> list[str]:
    out: list[str] = []
    for n in (name,):
        if n:
            out.append(n)
            if group:
                out += [f"{group}/{n}", f"{group}:{n}"]
    _, p, _ = _purl_parts(purl or "")
    if p:
        out += [p, p.replace("/", ":")]
    return list(dict.fromkeys(x.strip() for x in out if x and x.strip()))


def _simple_affected(entry: dict[str, Any], where: str) -> list[Affected]:
    pkg = entry.get("package")
    eco = None
    names: list[str] = []
    if isinstance(pkg, str):
        names = [pkg]
    elif isinstance(pkg, dict):
        t, p, _ = _purl_parts(str(pkg.get("purl") or ""))
        eco = _eco(pkg.get("ecosystem")) or _eco(t)
        names = _names_for(pkg.get("name"), None, pkg.get("purl"))
    else:
        raise ValueError(f"{where}: 'package' must be a name or mapping")
    eco = eco or _eco(entry.get("ecosystem"))
    if not names:
        raise ValueError(f"{where}: advisory has no package name")
    spec = entry.get("affected")
    specs = spec if isinstance(spec, list) else [spec] if spec is not None else []
    clauses = tuple(tuple(parse_constraints(str(s))) for s in specs)
    versions = frozenset(str(v) for v in (entry.get("versions") or []))
    if not clauses and not versions:
        raise ValueError(f"{where}: advisory needs 'affected' version ranges or 'versions'")
    fixed = entry.get("fixed")
    fx = tuple(str(x) for x in (fixed if isinstance(fixed, list) else [fixed] if fixed else []))
    return [Affected(tuple(_norm_name(n, eco) for n in names), eco, clauses, versions, fx)]


def _osv_affected(entry: dict[str, Any], where: str) -> list[Affected]:
    out = []
    for i, aff in enumerate(entry.get("affected") or []):
        if not isinstance(aff, dict) or not isinstance(aff.get("package", {}), dict):
            raise ValueError(f"{where}.affected[{i}] must be a mapping with a package")
        pkg = aff.get("package") or {}
        t, _, _ = _purl_parts(str(pkg.get("purl") or ""))
        eco = _eco(pkg.get("ecosystem")) or _eco(t)
        names = _names_for(pkg.get("name"), None, pkg.get("purl"))
        if not names:
            continue
        clauses, fixed = [], []
        for r in aff.get("ranges") or []:
            if not isinstance(r, dict) or str(r.get("type", "")).upper() not in {"SEMVER", "ECOSYSTEM"}:
                continue  # GIT ranges cannot be applied to a package version
            lo: str | None = None
            started = False
            for ev in r.get("events") or []:
                if not isinstance(ev, dict):
                    continue
                if "introduced" in ev:
                    lo, started = str(ev["introduced"]), True
                    if lo == "0":
                        lo = None
                elif started and "fixed" in ev:
                    clauses.append([(">=", lo)] * (lo is not None) + [("<", str(ev["fixed"]))]); fixed.append(str(ev["fixed"])); started = False
                elif started and "last_affected" in ev:
                    clauses.append([(">=", lo)] * (lo is not None) + [("<=", str(ev["last_affected"]))]); started = False
            if started:
                clauses.append([(">=", lo)] if lo is not None else [])
        versions = frozenset(str(v) for v in aff.get("versions") or [])
        if clauses or versions:
            out.append(Affected(tuple(_norm_name(n, eco) for n in names), eco, tuple(tuple(c) for c in clauses), versions, tuple(fixed)))
    return out


def _severity(entry: dict[str, Any], affected_raw: list[Any]) -> tuple[str, str]:
    s = _sev_word(entry.get("severity")) if isinstance(entry.get("severity"), str) else None
    if s:
        return s, "advisory 'severity'"
    ds = entry.get("database_specific")
    ds_sev = _sev_word(ds.get("severity")) if isinstance(ds, dict) else None
    if ds_sev:
        return ds_sev, "database_specific.severity"
    sev = entry.get("severity")
    if isinstance(sev, list):
        for item in sev:
            if not isinstance(item, dict):
                continue
            score = cvss3_score(str(item.get("score", "")))
            if score is not None:
                return _bucket(score), f"CVSS v3 base score {score} computed from the vector"
            try:
                return _bucket(float(item.get("score"))), "numeric severity score"
            except (TypeError, ValueError):
                pass
    for aff in affected_raw:
        es = aff.get("ecosystem_specific") if isinstance(aff, dict) else None
        es_sev = _sev_word(es.get("severity")) if isinstance(es, dict) else None
        if es_sev:
            return es_sev, "ecosystem_specific.severity"
    return "medium", "default: the advisory carries no usable severity"


def parse_advisories(data: Any, source: str = "advisories") -> AdvisoryDB:
    """Accept the simple format ({version, expires, advisories: [...]}) or an OSV subset
    (one vulnerability object, a list of them, or {version, expires, vulns: [...]}). Entries that are
    malformed raise ValueError with the entry position; unknown fields are ignored."""
    meta: dict[str, Any] = {}
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        if "advisories" in data or "vulns" in data:
            entries = data.get("advisories") if "advisories" in data else data.get("vulns")
            meta = data
        elif "id" in data and ("affected" in data or "package" in data):
            entries = [data]
        else:
            raise ValueError(f"{source}: expected an 'advisories' or 'vulns' list, or an OSV vulnerability object")
    else:
        raise ValueError(f"{source}: expected a mapping or a list")
    if not isinstance(entries, list):
        raise ValueError(f"{source}: advisories must be a list")
    entries = list(entries)
    if len(entries) > MAX_ADVISORIES:
        raise ValueError(f"{source}: more than {MAX_ADVISORIES} advisories")
    version = meta.get("version")
    if version is not None and not isinstance(version, (str, int, float, dt.date)):
        raise ValueError(f"{source}: 'version' must be a string or date")
    expires = _date(meta.get("expires"), "expires")
    db = AdvisoryDB(source, "osv" if any(isinstance(e, dict) and "affected" in e and "package" not in e for e in entries) else "simple",
                    None if version is None else str(version), expires)
    for i, e in enumerate(entries):
        where = f"{source}: entry {i}"
        if not isinstance(e, dict):
            raise ValueError(f"{where} must be a mapping")
        aid = e.get("id")
        if not isinstance(aid, str) or not aid.strip() or len(aid) > 100:
            raise ValueError(f"{where} needs a string 'id'")
        is_osv = "affected" in e and isinstance(e.get("affected"), list) and "package" not in e
        affected = _osv_affected(e, where) if is_osv else _simple_affected(e, where)
        if not affected:
            continue
        sev, src = _severity(e, e.get("affected") if is_osv else [])
        refs = e.get("references")
        url = str(e.get("url") or (refs[0].get("url") if isinstance(refs, list) and refs and isinstance(refs[0], dict) else "") or "")
        db.advisories.append(Advisory(_sanitize(aid.strip(), 100), tuple(_sanitize(a, 100) for a in (e.get("aliases") or []) if isinstance(a, str))[:10],
                                      _sanitize(e.get("summary") or e.get("details") or "", 160), sev, src, tuple(affected), _sanitize(url, 200)))
    return db


def load_advisories(path: str | Path) -> AdvisoryDB:
    p = Path(path)
    return parse_advisories(_load_doc(_read_bounded(p, "advisory file"), p.name), p.name)


# --------------------------------------------------------------------------- SBOMs

@dataclass(frozen=True)
class Component:
    names: tuple[str, ...]
    version: str
    ecosystem: str | None
    label: str


@dataclass
class Sbom:
    source: str
    fmt: str
    subjects: list[ImageRef]
    components: list[Component]
    explicit: bool = False  # subject given by the user or a kubeflight:image property


def _subject_ref(name: Any, version: Any) -> ImageRef | None:
    if not isinstance(name, str):
        return None
    ref = parse_image(name.strip())
    if ref is None:
        return None
    if not ref.tag and not ref.digest and isinstance(version, str) and version:
        v = version.strip()
        ref = parse_image(f"{name.strip()}@{v}") if v.startswith("sha256:") else parse_image(f"{name.strip()}:{v}") or ref
    return ref


def _walk_cdx(items: Any, out: list[Component], depth: int = 0) -> None:
    if not isinstance(items, list):
        return
    if depth > MAX_DEPTH:
        raise ValueError("CycloneDX components are nested too deeply")
    for c in items:
        if not isinstance(c, dict):
            continue
        if len(out) >= MAX_COMPONENTS:
            raise ValueError(f"SBOM has more than {MAX_COMPONENTS} components")
        name, ver, purl = c.get("name"), c.get("version"), c.get("purl")
        if isinstance(name, str) and name and isinstance(ver, (str, int, float)) and str(ver):
            t, _, _ = _purl_parts(purl if isinstance(purl, str) else "")
            eco = _eco(t)
            out.append(Component(tuple(_norm_name(n, eco) for n in _names_for(name, c.get("group") if isinstance(c.get("group"), str) else None, purl if isinstance(purl, str) else None)),
                                 str(ver), eco, f"{_sanitize(name, 80)}@{_sanitize(ver, 40)}"))
        _walk_cdx(c.get("components"), out, depth + 1)


def parse_sbom(data: Any, source: str = "sbom", image: str | None = None) -> Sbom:
    if not isinstance(data, dict):
        raise ValueError(f"{source}: SBOM must be a JSON object")
    comps: list[Component] = []
    subjects: list[ImageRef] = []
    explicit = False
    if data.get("bomFormat") == "CycloneDX":
        fmt = "cyclonedx"
        meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        mc = meta.get("component") if isinstance(meta.get("component"), dict) else {}
        for props in (meta.get("properties"), mc.get("properties")):
            for p in props if isinstance(props, list) else []:
                if isinstance(p, dict) and p.get("name") in {"kubeflight:image", "kubeflight.image"}:
                    r = parse_image(p.get("value"))
                    if r:
                        subjects.append(r); explicit = True
        if not subjects:
            r = _subject_ref(mc.get("name"), mc.get("version"))
            if r:
                subjects.append(r)
            _, pp, _ = _purl_parts(str(mc.get("purl") or ""))
            if pp and str(mc.get("purl")).startswith("pkg:oci/"):
                r = parse_image(pp)
                if r:
                    subjects.append(r)
        _walk_cdx(data.get("components"), comps)
    elif isinstance(data.get("spdxVersion"), str) and data["spdxVersion"].startswith("SPDX-2"):
        fmt = "spdx"
        pk = data.get("packages")
        if not isinstance(pk, list):
            raise ValueError(f"{source}: SPDX document has no 'packages' list")
        described = set()
        for d in data.get("documentDescribes") or []:
            if isinstance(d, str):
                described.add(d)
        for rel in data.get("relationships") or []:
            if isinstance(rel, dict) and rel.get("relationshipType") == "DESCRIBES" and isinstance(rel.get("relatedSpdxElement"), str):
                described.add(rel["relatedSpdxElement"])
        for p in pk:
            if not isinstance(p, dict):
                continue
            if len(comps) >= MAX_COMPONENTS:
                raise ValueError(f"SBOM has more than {MAX_COMPONENTS} components")
            purl = next((x.get("referenceLocator") for x in p.get("externalRefs") or [] if isinstance(x, dict) and x.get("referenceType") == "purl"), None)
            if p.get("SPDXID") in described:
                r = _subject_ref(p.get("name"), p.get("versionInfo"))
                if r:
                    subjects.append(r)
                continue
            name, ver = p.get("name"), p.get("versionInfo")
            if isinstance(name, str) and name and isinstance(ver, (str, int, float)) and str(ver):
                t, _, _ = _purl_parts(purl if isinstance(purl, str) else "")
                eco = _eco(t)
                comps.append(Component(tuple(_norm_name(n, eco) for n in _names_for(name, None, purl if isinstance(purl, str) else None)),
                                       str(ver), eco, f"{_sanitize(name, 80)}@{_sanitize(ver, 40)}"))
        if not subjects:
            r = _subject_ref(data.get("name"), None)
            if r:
                subjects.append(r)
    else:
        raise ValueError(f"{source}: not a CycloneDX JSON or SPDX 2.x JSON document (SPDX 3 / XML / tag-value are not supported)")
    if image is not None:
        r = parse_image(image)
        if r is None:
            raise ValueError(f"{source}: {_sanitize(image, 80)!r} is not a valid image reference")
        subjects, explicit = [r], True
    return Sbom(source, fmt, subjects, comps, explicit)


def load_sbom(spec: str | Path) -> Sbom:
    """``FILE`` or ``FILE=IMAGE`` (IMAGE overrides which workload image the SBOM describes)."""
    s = str(spec)
    image = None
    if not Path(s).exists() and "=" in s:
        s, image = s.rsplit("=", 1)
    p = Path(s)
    return parse_sbom(_load_doc(_read_bounded(p, "SBOM"), p.name), p.name, image)


def sbom_matches(sbom: Sbom, ref: ImageRef) -> bool:
    for s in sbom.subjects:
        if s.canonical_repo != ref.canonical_repo:
            continue
        if s.digest and ref.digest:
            if s.digest == ref.digest:
                return True
            continue
        st, wt = s.tag, ref.tag or ("latest" if not ref.digest else None)
        if st and wt and st != wt:
            continue
        return True
    return False


# --------------------------------------------------------------------------- findings

def vulnerability_findings(resources: list[dict[str, Any]], sboms: list[Sbom], dbs: list[AdvisoryDB], today: dt.date | None = None) -> list[Finding]:
    today = today or dt.date.today()
    out: list[Finding] = []
    for db in dbs:
        res = f"Advisories/{db.source}"
        if db.expires is not None and db.expired(today):
            out.append(Finding("KF-VUL-002", "medium", "supply-chain", "Advisory data is stale", res,
                               f"expired {db.expires.isoformat()}" + (f"; data version {_sanitize(db.version, 60)}" if db.version else ""),
                               "Refresh the advisory file from your vulnerability source and set a new expires date."))
        elif db.expires is None and db.version is None:
            out.append(Finding("KF-VUL-003", "low", "supply-chain", "Advisory data has no version or expiry", res,
                               "neither 'version' nor 'expires' is set, so staleness cannot be judged",
                               "Add version and expires fields (YYYY-MM-DD) when exporting the advisory file."))
    index: dict[str, list[tuple[Advisory, Affected, AdvisoryDB]]] = {}
    for db in dbs:
        for adv in db.advisories:
            for aff in adv.affected:
                for n in aff.names:
                    index.setdefault(n, []).append((adv, aff, db))
    used = [False] * len(sboms)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    seen_images: set[tuple[str, str, str]] = set()
    for rk, cname, raw in workload_images(resources):
        ref = parse_image(raw)
        if ref is None or (rk, ref.raw, cname) in seen_images:
            continue
        seen_images.add((rk, ref.raw, cname))
        matched = [(i, s) for i, s in enumerate(sboms) if sbom_matches(s, ref)]
        if not matched:
            if sboms:
                out.append(Finding("KF-VUL-005", "info", "supply-chain", f"No SBOM for image: {cname}", rk,
                                   f"image={_sanitize(raw)} matches none of the {len(sboms)} supplied SBOM(s)",
                                   "Supply an SBOM for this image (or FILE=IMAGE to bind one explicitly) if it should be covered."))
            continue
        for i, s in matched:
            used[i] = True
            for comp in s.components:
                for n in comp.names:
                    for adv, aff, db in index.get(n, ()):
                        if aff.ecosystem and comp.ecosystem and aff.ecosystem != comp.ecosystem:
                            continue
                        if not aff.matches_version(comp.version):
                            continue
                        g = grouped.setdefault((rk, adv.id), {"adv": adv, "aff": aff, "db": db, "comps": {}, "images": {}})
                        g["comps"][comp.label] = None
                        g["images"][f"{cname}={ref.raw}"] = None
    for (rk, _), g in sorted(grouped.items(), key=lambda kv: (SEVERITIES.index(kv[1]["adv"].severity), kv[0])):
        if len([f for f in out if f.id == "KF-VUL-001"]) >= MAX_VUL_FINDINGS:
            out.append(Finding("KF-VUL-006", "low", "supply-chain", "Vulnerability findings truncated", "ChangeSet",
                               f"more than {MAX_VUL_FINDINGS} matches; the most severe are shown", "Narrow the SBOM scope or fix the most severe matches first."))
            break
        adv: Advisory = g["adv"]
        aff: Affected = g["aff"]
        db: AdvisoryDB = g["db"]
        comps = list(g["comps"])
        ev = (f"{', '.join(comps[:5])}{' (+%d more)' % (len(comps) - 5) if len(comps) > 5 else ''} in {', '.join(list(g['images'])[:3])} "
              f"is in the affected range [{_describe([list(c) for c in aff.clauses], set(aff.versions))}]"
              + (f"; fixed in {', '.join(aff.fixed)}" if aff.fixed else "")
              + f"; severity={adv.severity} ({adv.severity_source}); advisory data {_sanitize(db.source, 60)}"
              + (f" version {_sanitize(db.version, 40)}" if db.version else "") + (f" expires {db.expires.isoformat()}" if db.expires else " has no expiry")
              + (f"; {adv.summary}" if adv.summary else "") + (f"; {adv.url}" if adv.url else ""))
        out.append(Finding("KF-VUL-001", adv.severity, "supply-chain", f"Known-vulnerable component ({adv.id})", rk, ev,
                           f"Update the affected component{' to ' + ' / '.join(aff.fixed) if aff.fixed else ''}, rebuild the image and regenerate the SBOM; or suppress with a reasoned, expiring entry if it is not exploitable."))
    for i, s in enumerate(sboms):
        if not used[i]:
            subj = ", ".join(r.raw for r in s.subjects) or "no image subject"
            out.append(Finding("KF-VUL-004", "low", "supply-chain", "SBOM matches no workload image", f"SBOM/{s.source}",
                               f"SBOM subject ({_sanitize(subj)}) does not match any image in the manifests",
                               "Bind it explicitly with --sbom FILE=IMAGE or add a 'kubeflight:image' property to the SBOM."))
    return out
