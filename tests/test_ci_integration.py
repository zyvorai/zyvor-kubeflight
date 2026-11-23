# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
import yaml
from fastapi.testclient import TestClient
from kubeflight.cli import main
from kubeflight.diffreport import normalize_report, diff_reports, load_report, pr_comment_report, diff_markdown, COMMENT_MARKER, MAX_COMMENT_CHARS
from kubeflight.engine import assess
from kubeflight.models import Finding
from kubeflight.server import app

ROOT = Path(__file__).parents[1]
DEMO = str(ROOT / "examples/demo/app.yaml")
UNSAFE = str(ROOT / "examples/unsafe/unsafe.yaml")


def rep(*fs, score=90):
    return {"score": score, "decision": "SAFE TO DEPLOY", "findings": [dict(id=i, severity=s, category="c", title=t, resource=r, evidence="e", recommendation="x") for i, s, t, r in fs]}


def test_diff_new_resolved_unchanged_and_escalation():
    old = normalize_report(rep(("KF-A-1", "low", "t", "R/a"), ("KF-B-1", "high", "t", "R/b"), ("KF-C-1", "low", "t", "R/c")))
    new = normalize_report(rep(("KF-A-1", "low", "t", "R/a"), ("KF-C-1", "high", "t", "R/c"), ("KF-D-1", "medium", "t", "R/d")), )
    d = diff_reports(old, new)
    assert [f["id"] for f in d["new"]] == ["KF-C-1", "KF-D-1"] and d["new"][0]["previous_severity"] == "low"
    assert [f["id"] for f in d["resolved"]] == ["KF-B-1"] and d["unchanged"] == 1
    assert d["states"] == ["unchanged", "new", "new"]

def test_diff_evidence_churn_is_not_new_and_duplicates_are_counted():
    a = rep(("KF-A-1", "low", "t", "R/a"), ("KF-A-1", "low", "t", "R/a"))
    b = rep(("KF-A-1", "low", "t", "R/a"), ("KF-A-1", "low", "t", "R/a"), ("KF-A-1", "low", "t", "R/a"))
    b["findings"][0]["evidence"] = "changed"
    assert len(diff_reports(normalize_report(a), normalize_report(b))["new"]) == 1

@pytest.mark.parametrize("bad", [[], "x", {}, {"findings": "x"}, {"findings": [5]}, {"findings": [{"id": "a"}]},
                                 {"findings": [{"id": "a", "severity": "wat", "resource": "r", "title": "t"}]},
                                 {"findings": [{"id": 1, "severity": "low", "resource": "r", "title": "t"}]}])
def test_report_validation_rejects_hostile_input(bad):
    with pytest.raises(ValueError):
        normalize_report(bad)

def test_load_report_errors(tmp_path):
    p = tmp_path / "r.json"
    p.write_text("{nope")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_report(p)
    p.write_text("[" * 200000)
    with pytest.raises(ValueError):
        load_report(p)

def test_markdown_escapes_manifest_text():
    f = ("KF-A-1", "high", "evil | `x` <b>@octocat [click](http://x)\nnewline", "Deployment/default/@bob|x")
    d = diff_reports(normalize_report(rep()), normalize_report(rep(f)))
    md = diff_markdown(d)
    assert "@octocat" not in md and "@bob" not in md and "<b>" not in md and "[click](" not in md and "\nnewline" not in md
    assert md.count("\n| HIGH") == 1  # still exactly one table row

def test_pr_comment_is_size_capped_and_has_marker():
    findings = [Finding(f"KF-X-{i}", "low", "c", "t" * 400, "R/" + "r" * 300, "e", "r") for i in range(3000)]
    res = assess([], extra=findings)
    old = normalize_report(rep())
    diff = diff_reports(old, normalize_report(res.to_dict()))
    text = pr_comment_report(res, diff)
    assert text.startswith(COMMENT_MARKER) and len(text) <= MAX_COMMENT_CHARS

def _json(tmp_path, name, *args):
    out = tmp_path / name
    main(["check", *args, "--format", "json", "--output", str(out), "--fail-on", "never"])
    return out

def test_cli_diff_report_and_fail_on_new(tmp_path, capsys):
    old = _json(tmp_path, "old.json", DEMO)
    new = _json(tmp_path, "new.json", UNSAFE)
    assert main(["diff-report", str(old), str(old), "--fail-on-new"]) == 0
    assert main(["diff-report", str(old), str(new), "--fail-on-new"]) == 3
    assert main(["diff-report", str(old), str(new), "--fail-on-new", "info", "--format", "markdown"]) == 3
    out = capsys.readouterr().out
    assert COMMENT_MARKER in out and "New findings vs baseline" in out
    assert main(["diff-report", str(old), str(new)]) == 0                       # no gate unless asked
    assert main(["diff-report", str(old), str(new), "--format", "json"]) == 0 and "states" not in capsys.readouterr().out
    assert main(["diff-report", str(old), str(tmp_path / "missing.json")]) == 2

def test_check_baseline_report_only_new_findings_gate(tmp_path, capsys):
    base = _json(tmp_path, "base.json", UNSAFE)
    # identical to the baseline: the unsafe example has criticals, but nothing is new
    assert main(["check", UNSAFE, "--baseline-report", str(base), "--fail-on-new", "--format", "json", "--output", str(tmp_path / "o.json")]) == 0
    assert json.loads((tmp_path / "o.json").read_text())["diff"]["new"] == []
    assert main(["check", UNSAFE, "--fail-on", "critical", "--format", "json", "--output", str(tmp_path / "o2.json")]) == 3
    clean = _json(tmp_path, "clean.json", DEMO)
    assert main(["check", UNSAFE, "--baseline-report", str(clean), "--fail-on-new", "high", "--format", "json", "--output", str(tmp_path / "o3.json")]) == 3

def test_fail_on_new_needs_baseline_report(capsys):
    assert main(["check", DEMO, "--fail-on-new"]) == 2 and "--baseline-report" in capsys.readouterr().err

def test_all_formats_with_baseline_report(tmp_path):
    clean = _json(tmp_path, "clean.json", DEMO)
    for fmt in ("text", "json", "markdown", "html", "sarif", "pr-comment"):
        out = tmp_path / f"o.{fmt}"
        assert main(["check", UNSAFE, "--baseline-report", str(clean), "--format", fmt, "--output", str(out), "--fail-on", "never"]) == 0
        assert out.read_text()
    sarif = json.loads((tmp_path / "o.sarif").read_text())
    assert {r["baselineState"] for r in sarif["runs"][0]["results"]} <= {"new", "unchanged"} and sarif["runs"][0]["results"][0]["baselineState"] == "new"
    pr = (tmp_path / "o.pr-comment").read_text()
    assert pr.startswith(COMMENT_MARKER) and "New findings vs baseline" in pr and "<details>" in pr
    assert "New findings vs baseline" in (tmp_path / "o.markdown").read_text()

def test_pr_comment_without_baseline(tmp_path):
    out = tmp_path / "c.md"
    main(["check", UNSAFE, "--format", "pr-comment", "--output", str(out), "--fail-on", "never"])
    t = out.read_text()
    assert t.startswith(COMMENT_MARKER) and "New findings" not in t and "All findings" in t

def test_min_severity_applies_to_diff_view_but_gate_sees_all(tmp_path):
    clean = _json(tmp_path, "clean.json", DEMO)
    out = tmp_path / "o.json"
    rc = main(["check", UNSAFE, "--baseline-report", str(clean), "--min-severity", "critical", "--fail-on-new", "high", "--format", "json", "--output", str(out)])
    d = json.loads(out.read_text())
    assert rc == 3 and all(f["severity"] == "critical" for f in d["diff"]["new"])


# ---- API ------------------------------------------------------------------

client = TestClient(app)

def test_api_rules_explain_and_profiles():
    r = client.get("/api/rules/kf-img-001")
    assert r.status_code == 200 and r.json()["id"] == "KF-IMG-001" and r.json()["rationale"]
    assert client.get("/api/rules/KF-NOPE-1").status_code == 404
    assert client.get("/api/rules/" + "A" * 5000).status_code == 404
    assert len(client.get("/api/rules").json()["rules"]) > 80
    assert {p["name"] for p in client.get("/api/profiles").json()["profiles"]} == {"baseline", "permissive", "restricted", "strict"}

def test_api_check_with_profile_supply_chain_and_diff():
    demo = (ROOT / "examples/demo/app.yaml").read_text()
    sup = ROOT / "examples/supply"
    body = {"manifests": demo, "profile": "strict",
            "sboms": [{"document": json.loads((sup / "sbom.cdx.json").read_text())}],
            "advisories": [json.loads((sup / "advisories.osv.json").read_text()), {"version": "1", "expires": "2099-01-01", "advisories": [{"id": "D-1", "package": "openssl", "affected": ["<3.0.13"], "severity": "high"}]}],
            "image_policy": {"allowed_registries": ["registry.example.com"]},
            "baseline_report": {"findings": []}}
    r = client.post("/api/check", json=body)
    d = r.json()
    assert r.status_code == 200 and d["profile"]["name"] == "strict" and {"KF-VUL-001", "KF-IMG-003"} <= {f["id"] for f in d["findings"]}
    assert len(d["diff"]["new"]) == len(d["findings"]) and any("not a vulnerability scanner" in l for l in d["limitations"])

@pytest.mark.parametrize("patch", [{"profile": "nope"}, {"profile_spec": {"disable": ["KF-NOPE-1"]}}, {"image_policy": {"x": 1}}, {"sboms": [{"document": "x"}]},
                                   {"advisories": [{"advisories": [5]}]}, {"baseline_report": {"findings": "x"}},
                                   {"sboms": [{"document": {"bomFormat": "CycloneDX"}}]}])
def test_api_check_hostile_input_is_400(patch):
    r = client.post("/api/check", json={"manifests": (ROOT / "examples/demo/app.yaml").read_text(), **patch})
    assert r.status_code == 400

def test_api_values_and_diff():
    r = client.post("/api/values", json={"values": (ROOT / "examples/helm/values.yaml").read_text(), "profile": "permissive"})
    d = r.json()
    assert r.status_code == 200 and d["findings"] and "changeme" not in json.dumps(d)
    assert client.post("/api/values", json={"values": "a: [1, 2\n"}).status_code == 400
    assert client.post("/api/values", json={"values": "x: 1", "profile": "nope"}).status_code == 400
    old, new = {"findings": []}, {"findings": [{"id": "KF-A-1", "severity": "low", "resource": "r", "title": "t"}]}
    assert len(client.post("/api/diff", json={"old": old, "new": new}).json()["new"]) == 1
    assert client.post("/api/diff", json={"old": {}, "new": new}).status_code == 400

def test_web_dashboard_has_explain_and_suppression_ui():
    html = client.get("/").text
    assert "/api/rules/" in html and 'id="suppsec"' in html and "showSuppressed" in html


# ---- GitHub Action --------------------------------------------------------

def test_action_yml_exposes_features_and_script_runs(tmp_path):
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    for k in ("profile", "profile-file", "baseline-report", "fail-on-new", "sbom", "advisories", "image-policy", "allow-registry", "pr-comment"):
        assert k in action["inputs"]
    assert "pr-comment" in action["outputs"]
    step = [s for s in action["runs"]["steps"] if s.get("env")][0]
    assert "${{" not in step["run"]  # no expression injection into the script
    base = tmp_path / "base.json"
    main(["check", DEMO, "--format", "json", "--output", str(base), "--fail-on", "never"])
    bindir = tmp_path / "bin"; bindir.mkdir()
    (bindir / "kubeflight").write_text(f"#!/bin/sh\nexec {sys.executable} -m kubeflight \"$@\"\n"); (bindir / "kubeflight").chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "PYTHONPATH": str(ROOT), "GITHUB_STEP_SUMMARY": str(tmp_path / "step.md"),
           "INPUT_PATH": UNSAFE, "INPUT_BASELINE": "", "INPUT_FAIL_ON": "critical", "INPUT_PROFILE": "baseline", "INPUT_PROFILE_FILE": "",
           "INPUT_BASELINE_REPORT": str(base), "INPUT_FAIL_ON_NEW": "high", "INPUT_IMAGE_POLICY": "", "INPUT_ALLOW_REGISTRY": "ghcr.io/x\nregistry.example.com\n",
           "INPUT_SBOM": "", "INPUT_ADVISORIES": "", "JSON_OUT": str(tmp_path / "r.json"), "SARIF_OUT": str(tmp_path / "r.sarif"),
           "SUMMARY_OUT": str(tmp_path / "s.md"), "COMMENT_OUT": str(tmp_path / "c.md")}
    p = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]], env=env, capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 3, p.stderr                                   # new high/critical findings fail the gate...
    assert "New findings vs baseline" in (tmp_path / "step.md").read_text()  # ...but the summary was still published
    assert (tmp_path / "c.md").read_text().startswith(COMMENT_MARKER) and (tmp_path / "r.sarif").exists()
