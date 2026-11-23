# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import json
from pathlib import Path
import pytest
from kubeflight.cli import main
from kubeflight.engine import assess
from kubeflight.helmvalues import values_findings, load_values, MAX_FILE_BYTES, MAX_NODES
from kubeflight.registry import REGISTRY
from kubeflight.report import sarif_report, markdown_report, json_report, html_report, text_report

ROOT = Path(__file__).parents[1]
EX = ROOT / "examples" / "helm" / "values.yaml"


def run(text):
    return values_findings(text, "values.yaml")[0]

def ids(fs): return [f.id for f in fs]


def test_example_values_hit_every_check():
    fs = run(EX.read_text())
    assert set(ids(fs)) == {"KF-HLM-001", "KF-HLM-002", "KF-HLM-003", "KF-HLM-004", "KF-HLM-005", "KF-HLM-006", "KF-HLM-007"} and set(ids(fs)) <= set(REGISTRY)

def test_secret_values_are_never_printed():
    text = "db:\n  password: Sup3rS3cretValue\n  apiKey: AKIA1234567890SECRET\nadmin:\n  password: changeme\n"
    out = json.dumps([f.to_dict() for f in run(text)])
    for secret in ("Sup3rS3cretValue", "AKIA1234567890SECRET", "changeme"):
        assert secret not in out
    assert ids(run(text)).count("KF-HLM-006") == 1 and ids(run(text)).count("KF-HLM-007") == 2

def test_secret_references_and_templates_are_not_flagged():
    text = "auth:\n  existingSecret: my-secret\n  passwordKey: password\n  secretName: s\n  password: ''\n  token: '{{ .Values.x }}'\n  apiKey: ${API_KEY}\n  tokenEnabled: true\n"
    assert ids(run(text)) == []

def test_bool_flags_and_safe_values():
    assert ids(run("securityContext: {privileged: false, allowPrivilegeEscalation: false, runAsNonRoot: true, runAsUser: 1000}\nhostNetwork: false\n")) == []
    fs = run("a: {privileged: true, allowPrivilegeEscalation: yes, hostPID: true, hostIPC: on, runAsNonRoot: false, runAsUser: 0}\n")
    assert ids(fs).count("KF-HLM-001") == 6

def test_latest_tag_variants():
    assert ids(run("image: {tag: latest}\n")) == ["KF-HLM-003"]
    assert ids(run("image: nginx:latest\n")) == ["KF-HLM-003"]
    assert ids(run("image: {tag: Stable}\n")) == ["KF-HLM-003"]
    assert ids(run("image: {tag: '1.2.3'}\n")) == []

def test_resources_and_ingress():
    assert ids(run("resources: {}\n")) == ["KF-HLM-004"]
    assert ids(run("resources: {limits: {cpu: 1}}\n")) == ["KF-HLM-004"]
    assert ids(run("resources: {requests: {cpu: 100m, memory: ''}}\n")) == ["KF-HLM-004"]
    assert ids(run("resources: {requests: {cpu: 100m, memory: 64Mi}}\n")) == []
    assert ids(run("ingress: {enabled: false}\n")) == []
    assert ids(run("ingress: {enabled: true, tls: []}\n")) == ["KF-HLM-005"]
    assert ids(run("ingress: {enabled: true, tls: [{secretName: x}]}\n")) == []

def test_locations_and_resources_name_the_key_path():
    fs, locs = values_findings("a:\n  b:\n    hostNetwork: true\n", "/tmp/chart/values.yaml")
    assert fs[0].resource == "Values/values.yaml:a.b.hostNetwork" and locs[fs[0].resource] == ("/tmp/chart/values.yaml", 3)

@pytest.mark.parametrize("text", ["", "# only a comment\n", "- a\n- b\n", "just a scalar", "null", "{}", "a: [1, 2\n"])
def test_degenerate_documents(text):
    try:
        assert run(text) == []
    except ValueError as e:
        assert "invalid YAML" in str(e)

def test_alias_bomb_is_bounded():
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"] + [f"a{i}: &a{i} [{', '.join([f'*a{i-1}'] * 10)}]" for i in range(1, 12)]
    with pytest.raises(ValueError, match="too many nodes"):
        run("\n".join(lines) + "\n")

def test_depth_and_size_bounds():
    with pytest.raises(ValueError, match="nested too deeply"):
        run("".join("  " * i + f"k{i}:\n" for i in range(60)) + "  " * 60 + "x: 1\n")
    with pytest.raises(ValueError, match="larger"):
        run("a: " + "x" * (MAX_FILE_BYTES + 10))

def test_directory_and_missing_paths(tmp_path):
    (tmp_path / "values.yaml").write_text("hostNetwork: true\n"); (tmp_path / "values-prod.yml").write_text("ingress: {enabled: true}\n")
    fs, _, n = load_values([str(tmp_path)])
    assert n == 2 and set(ids(fs)) == {"KF-HLM-002", "KF-HLM-005"}
    with pytest.raises(ValueError):
        load_values([str(tmp_path / "nope")])
    empty = tmp_path / "e"; empty.mkdir()
    with pytest.raises(ValueError, match="No values"):
        load_values([str(empty)])

def test_cli_values_all_formats_and_gate(tmp_path, capsys):
    for fmt in ("text", "json", "markdown", "html", "sarif", "pr-comment"):
        out = tmp_path / f"o.{fmt}"
        assert main(["values", str(EX), "--format", fmt, "--output", str(out), "--fail-on", "never"]) == 0
        body = out.read_text()
        assert "changeme" not in body and "not-a-real-token" not in body
    sarif = json.loads((tmp_path / "o.sarif").read_text())
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["region"]["startLine"] >= 1 and loc["logicalLocations"][0]["fullyQualifiedName"].startswith("Values/")
    assert main(["values", str(EX)]) == 0            # high findings, default gate is critical
    assert main(["values", str(EX), "--fail-on", "high"]) == 3
    assert main(["values", str(EX), "--profile", "permissive", "--format", "json", "--output", str(tmp_path / "p.json")]) == 0
    assert all(f["severity"] in ("high", "critical") for f in json.loads((tmp_path / "p.json").read_text())["findings"])
    assert main(["values", str(tmp_path / "missing.yaml")]) == 2

def test_ignore_file_suppresses_values_findings(tmp_path):
    ign = tmp_path / "i.yaml"; ign.write_text("ignore:\n- {id: KF-HLM-002, resource: 'Values/*', reason: node agent needs it, expires: 2099-01-01}\n")
    out = tmp_path / "o.json"
    main(["values", str(EX), "--ignore-file", str(ign), "--format", "json", "--output", str(out), "--fail-on", "never"])
    d = json.loads(out.read_text())
    assert "KF-HLM-002" not in [f["id"] for f in d["findings"]] and d["suppressed"][0]["id"] == "KF-HLM-002"
