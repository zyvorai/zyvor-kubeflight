# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Compare two KubeFlight JSON reports and render PR/CI friendly output that shows only what a change introduced."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .registry import SEVERITIES, SEVERITY_RANK

MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 200_000
COMMENT_MARKER = "<!-- kubeflight-pr-comment -->"
MAX_COMMENT_CHARS = 60_000  # GitHub rejects PR comments above 65,536 characters
_ORDER = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # critical first


def normalize_report(data: Any, name: str = "report") -> dict[str, Any]:
    """Validate the parts of a KubeFlight JSON report that the diff relies on and return a clean copy."""
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"{name}: not a KubeFlight JSON report (expected an object with a 'findings' list)")
    if len(data["findings"]) > MAX_FINDINGS:
        raise ValueError(f"{name}: more than {MAX_FINDINGS} findings")
    findings = []
    for i, f in enumerate(data["findings"]):
        if not isinstance(f, dict) or not all(isinstance(f.get(k), str) and f.get(k) for k in ("id", "severity", "resource", "title")):
            raise ValueError(f"{name}: findings[{i}] needs string id, severity, resource and title")
        if f["severity"] not in SEVERITIES:
            raise ValueError(f"{name}: findings[{i}] has unknown severity {f['severity'][:20]!r}")
        findings.append({"id": f["id"], "severity": f["severity"], "category": str(f.get("category") or ""), "title": f["title"],
                         "resource": f["resource"], "evidence": str(f.get("evidence") or ""), "recommendation": str(f.get("recommendation") or "")})
    score = data.get("score")
    return {"findings": findings, "score": score if isinstance(score, int) and not isinstance(score, bool) else None,
            "decision": data.get("decision") if isinstance(data.get("decision"), str) else None}


def load_report(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if p.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"{p.name}: report is larger than {MAX_REPORT_BYTES // 1024 // 1024} MiB")
    try:
        return normalize_report(json.loads(p.read_text(encoding="utf-8")), p.name)
    except RecursionError as e:
        raise ValueError(f"{p.name}: JSON is nested too deeply") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"{p.name}: invalid JSON: {e}") from e


def diff_reports(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Findings are matched on (id, resource, title); evidence is ignored so line or value churn is not 'new'.
    A finding whose severity rose since the old report counts as new (``previous_severity`` is set)."""
    pool: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for f in old["findings"]:
        pool.setdefault((f["id"], f["resource"], f["title"]), []).append(f)
    introduced, states, unchanged = [], [], 0
    for f in new["findings"]:
        prev = pool.get((f["id"], f["resource"], f["title"]))
        if not prev:
            introduced.append(dict(f)); states.append("new"); continue
        o = prev.pop(0)
        if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[o["severity"]]:
            introduced.append(dict(f, previous_severity=o["severity"])); states.append("new")
        else:
            unchanged += 1; states.append("unchanged")
    resolved = [f for lst in pool.values() for f in lst]
    key = lambda f: (_ORDER[f["severity"]], f["id"], f["resource"])
    introduced.sort(key=key); resolved.sort(key=key)
    return {"new": introduced, "resolved": resolved, "unchanged": unchanged, "states": states,
            "score_old": old.get("score"), "score_new": new.get("score"), "decision_old": old.get("decision"), "decision_new": new.get("decision"),
            "new_by_severity": {s: sum(1 for f in introduced if f["severity"] == s) for s in reversed(SEVERITIES)}}


def new_findings_at_or_above(diff: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    floor = SEVERITY_RANK[severity]
    return [f for f in diff["new"] if SEVERITY_RANK[f["severity"]] >= floor]


def _cell(v: Any) -> str:
    s = str(v).replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("[", "\\[").replace("]", "\\]").replace("\r", " ").replace("\n", " ")
    return s.replace("@", "@\u200b")  # never @-mention people from manifest-controlled text


def _table(rows: list[dict[str, Any]], limit: int) -> list[str]:
    out = ["| Severity | Id | Resource | Finding |", "|---|---|---|---|"]
    for f in rows[:limit]:
        sev = f["severity"].upper() + (f" (was {f['previous_severity']})" if f.get("previous_severity") else "")
        out.append(f"| {sev} | `{_cell(f['id'])}` | `{_cell(f['resource'])}` | {_cell(f['title'])} |")
    if len(rows) > limit:
        out.append(f"| | | | _{len(rows) - limit} more not shown_ |")
    return out


def _delta(a, b) -> str:
    return "n/a" if a is None or b is None else f"{a} -> {b} ({b - a:+d})"


def diff_markdown(diff: dict[str, Any], limit: int = 50) -> str:
    n = len(diff["new"])
    sev = ", ".join(f"{c} {s}" for s, c in diff["new_by_severity"].items() if c) or "none"
    lines = [f"### New findings vs baseline: {n}", "",
             f"**{n} new** ({sev}) · {len(diff['resolved'])} resolved · {diff['unchanged']} unchanged · score {_delta(diff['score_old'], diff['score_new'])}"
             + (f" · decision {_cell(diff['decision_old'])} -> {_cell(diff['decision_new'])}" if diff["decision_old"] and diff["decision_new"] and diff["decision_old"] != diff["decision_new"] else ""), ""]
    lines += _table(diff["new"], limit) if n else ["No new findings introduced by this change."]
    if diff["resolved"]:
        lines += ["", f"<details><summary>Resolved by this change ({len(diff['resolved'])})</summary>", ""] + _table(diff["resolved"], 25) + ["", "</details>"]
    return "\n".join(lines) + "\n"


def pr_comment_report(a, diff: dict[str, Any] | None = None) -> str:
    """Markdown for a PR comment or GITHUB_STEP_SUMMARY: hidden marker (for update-in-place), headline, new-vs-baseline
    section when a baseline report is supplied, and the full finding list collapsed. Kept under GitHub's comment size limit."""
    d = a.to_dict()
    icon = "✅" if d["decision"] == "SAFE TO DEPLOY" else ("⚠️" if d["decision"] == "REVIEW REQUIRED" else "⛔")
    head = [COMMENT_MARKER, f"## ✈️ KubeFlight: {icon} {_cell(d['decision'])}", "",
            f"**Safety score:** {d['score']}/100 · **Resources:** {d['resources']} · **Findings:** {len(d['findings'])}"
            + (f" · **Profile:** {_cell(d['profile']['name'])}" if d.get("profile") else ""), ""]
    findings = sorted(d["findings"], key=lambda f: (_ORDER[f["severity"]] if f["severity"] in _ORDER else 9, f["id"], f["resource"]))
    tail = ["", "_KubeFlight is a preflight simulator, not a substitute for admission control or production validation._"]
    text = ""
    for diff_limit, all_limit in ((50, 100), (20, 30), (5, 0)):
        body = []
        if diff is not None:
            body += [diff_markdown(diff, diff_limit)]
        if findings and all_limit:
            body += ["", f"<details><summary>All findings ({len(findings)})</summary>", ""] + _table(findings, all_limit) + ["", "</details>"]
        elif findings and diff is None:
            body += _table(findings, 10)
        text = "\n".join(head + body + tail) + "\n"
        if len(text) <= MAX_COMMENT_CHARS:
            return text
    return text[:MAX_COMMENT_CHARS - 200] + "\n\n_Output truncated to fit the comment size limit._\n"


def text_diff(diff: dict[str, Any]) -> str:
    lines = [f"New findings: {len(diff['new'])}   Resolved: {len(diff['resolved'])}   Unchanged: {diff['unchanged']}   Score: {_delta(diff['score_old'], diff['score_new'])}", ""]
    for f in diff["new"]:
        lines.append(f"+ [{f['severity'].upper():8}] {f['id']} {f['resource']} - {f['title']}" + (f" (was {f['previous_severity']})" if f.get("previous_severity") else ""))
    for f in diff["resolved"]:
        lines.append(f"- [{f['severity'].upper():8}] {f['id']} {f['resource']} - {f['title']}")
    return "\n".join(lines) + "\n"
