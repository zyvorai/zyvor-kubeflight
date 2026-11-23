# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import fnmatch
import json
from pathlib import Path
import pytest
from kubeflight.cli import main
from kubeflight.engine import assess
from kubeflight.models import Finding
from kubeflight.parser import load_path
from kubeflight.profiles import (builtin_names, builtin_profile, parse_profile, load_profile, apply_profile, referenced_patterns, PROFILE_DIR, MAX_FILE_BYTES)
from kubeflight.registry import REGISTRY

ROOT = Path(__file__).parents[1]
DOC = (ROOT / "docs" / "PROFILES.md").read_text()
PRESETS = ["baseline", "permissive", "restricted", "strict"]


def F(fid, sev, res="Deployment/default/x"):
    return Finding(fid, sev, "t", "title", res, "e", "r")


def test_presets_exist_as_data_files():
    assert builtin_names() == PRESETS and all((PROFILE_DIR / f"{n}.yaml").exists() for n in PRESETS)

@pytest.mark.parametrize("name", PRESETS)
def test_every_referenced_id_exists_in_registry(name):
    pats = referenced_patterns(builtin_profile(name))
    for p in pats:
        assert any(fnmatch.fnmatchcase(i, p) for i in REGISTRY), f"{name}: {p} matches no registry id"

@pytest.mark.parametrize("name", PRESETS)
def test_every_preset_is_documented_with_its_ids(name):
    p = builtin_profile(name)
    assert f"## `{name}`" in DOC
    section = DOC.split(f"## `{name}`", 1)[1].split("\n## ", 1)[0]
    assert p.description.split(".")[0] in section or name in section
    last = p.layers[-1]
    for pat in {x for x, _ in last.severity} | set(last.enable) | set(last.disable):
        assert pat in section, f"docs/PROFILES.md section {name} does not mention {pat}"
    assert f"fail_on: {p.fail_on}" in section and f"min_severity: {p.min_severity}" in section

def test_docs_do_not_mention_unknown_profile_sections():
    import re
    assert set(re.findall(r"^## `([a-z]+)`", DOC, re.M)) == set(PRESETS)

def test_preset_behaviour_on_unsafe_example():
    res = load_path(ROOT / "examples/unsafe/unsafe.yaml")
    out = {n: assess(res, profile=builtin_profile(n)) for n in PRESETS}
    none = assess(res)
    assert out["permissive"].summary["low"] == 0 and out["permissive"].summary["medium"] == 0
    assert len(out["permissive"].findings) < len(out["baseline"].findings) <= len(none.findings)
    assert len(out["strict"].findings) >= len(out["restricted"].findings)
    assert out["strict"].profile["name"] == "strict" and out["permissive"].profile["dropped"]

def test_severity_override_enable_disable_and_min_severity():
    prof = parse_profile({"min_severity": "medium", "severity": {"KF-SEC-030": "high", "KF-NET-*": "medium"}, "disable": ["KF-REL-003"], "enable": ["KF-REL-004"]}, "t")
    fs, rep = apply_profile([F("KF-SEC-030", "low"), F("KF-NET-010", "low"), F("KF-REL-003", "medium"), F("KF-REL-004", "low"), F("KF-SEC-023", "low")], prof)
    got = {f.id: f.severity for f in fs}
    assert got == {"KF-SEC-030": "high", "KF-NET-010": "medium", "KF-REL-004": "low"}  # enable beats min_severity; disable drops; others below min dropped
    assert rep["dropped"] == {"KF-REL-003": 1, "KF-SEC-023": 1} and rep["adjusted"]["KF-SEC-030"] == "low->high"

def test_exact_id_beats_pattern_within_a_layer():
    prof = parse_profile({"severity": {"KF-SEC-0*": "info", "KF-SEC-030": "high"}}, "t")
    fs, _ = apply_profile([F("KF-SEC-030", "low"), F("KF-SEC-023", "low")], prof)
    assert {f.id: f.severity for f in fs} == {"KF-SEC-030": "high", "KF-SEC-023": "info"}

def test_critical_findings_cannot_be_hidden_or_lowered():
    prof = parse_profile({"min_severity": "critical", "disable": ["KF-SEC-020"], "severity": {"KF-SEC-020": "low"}}, "t")
    fs, rep = apply_profile([F("KF-SEC-020", "critical"), F("KF-SEC-021", "high")], prof)
    assert [(f.id, f.severity) for f in fs] == [("KF-SEC-020", "critical")] and rep["protected_critical"] == ["KF-SEC-020"]
    # raising is allowed
    up, _ = apply_profile([F("KF-SEC-021", "high")], parse_profile({"severity": {"KF-SEC-021": "critical"}}, "t"))
    assert up[0].severity == "critical"

def test_score_and_decision_follow_the_profile():
    res = load_path(ROOT / "examples/demo/app.yaml")
    base, perm = assess(res), assess(res, profile=builtin_profile("permissive"))
    assert perm.score >= base.score

def test_extends_layers_and_user_file(tmp_path):
    f = tmp_path / "mine.yaml"
    f.write_text("name: mine\nextends: restricted\nfail_on: never\ndisable: ['KF-NET-0*']\nseverity: {KF-SUP-001: low}\n")
    p = load_profile(file=f)
    assert p.name == "mine" and p.fail_on == "never" and p.min_severity == "low"
    fs, _ = apply_profile([F("KF-NET-010", "low"), F("KF-SUP-001", "medium")], p)
    assert [(x.id, x.severity) for x in fs] == [("KF-SUP-001", "low")]
    g = tmp_path / "plain.yaml"; g.write_text("min_severity: high\n")
    assert load_profile("strict", g).min_severity == "high" and load_profile("strict", g).layers[0].name

def test_custom_rule_ids_allowed_but_unknown_ids_rejected():
    assert parse_profile({"disable": ["KF-CUS-001"]}, "t")
    for bad in ({"disable": ["KF-NOPE-999"]}, {"severity": {"KF-SEC-030": "urgent"}}, {"min_severity": "x"}, {"fail_on": "info"}, {"extends": "nope"}, {"extends": 5},
                {"unknown": 1}, {"disable": "KF-SEC-030"}, {"disable": [1]}, {"name": 5}, {"severity": []}, [], "x"):
        with pytest.raises(ValueError):
            parse_profile(bad, "t")

def test_profile_file_hostile(tmp_path, capsys):
    big = tmp_path / "big.yaml"; big.write_text("#" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="too large"):
        load_profile(file=big)
    bad = tmp_path / "bad.yaml"; bad.write_text("a: [unclosed")
    assert main(["check", str(ROOT / "examples/demo/app.yaml"), "--profile-file", str(bad)]) == 2
    assert "invalid profile" in capsys.readouterr().err
    anchors = tmp_path / "a.yaml"; anchors.write_text("disable: &a ['KF-SEC-030']\nenable: *a\n")
    assert parse_profile(__import__("yaml").safe_load(anchors.read_text()), "t")  # aliases are plain data

def test_cli_profile_sets_default_gate_and_explicit_fail_on_wins(capsys):
    unsafe = str(ROOT / "examples/unsafe/unsafe.yaml")
    assert main(["check", unsafe, "--profile", "permissive"]) == 3          # criticals still count
    demo = str(ROOT / "examples/demo/app.yaml")
    rc_default = main(["check", demo, "--format", "json", "--output", "/dev/null"])
    assert rc_default == 0
    assert main(["check", demo, "--profile", "strict", "--format", "json", "--output", "/dev/null"]) == 3   # strict gates on medium
    assert main(["check", demo, "--profile", "strict", "--fail-on", "never", "--format", "json", "--output", "/dev/null"]) == 0

def test_cli_profile_in_every_format(tmp_path):
    unsafe = str(ROOT / "examples/unsafe/unsafe.yaml")
    for fmt in ("text", "json", "markdown", "html", "sarif", "pr-comment"):
        out = tmp_path / f"o.{fmt}"
        assert main(["check", unsafe, "--profile", "baseline", "--format", fmt, "--output", str(out), "--fail-on", "never"]) == 0
        assert out.read_text()
    d = json.loads((tmp_path / "o.json").read_text())
    assert d["profile"]["name"] == "baseline" and "dropped" in d["profile"]
    assert "Profile: baseline" in (tmp_path / "o.markdown").read_text().replace("**", "")

def test_cli_unknown_profile_and_profiles_command(capsys):
    with pytest.raises(SystemExit):
        main(["check", "x", "--profile", "nope"])
    assert main(["profiles", "list"]) == 0 and "strict" in capsys.readouterr().out
    assert main(["profiles", "show", "restricted"]) == 0 and json.loads(capsys.readouterr().out)["name"] == "restricted"
    assert main(["profiles", "show", "nope"]) == 2
