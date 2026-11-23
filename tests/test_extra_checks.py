# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import datetime as dt
import pytest
from kubeflight.engine import assess
from kubeflight.parser import parse_text
from kubeflight.suppress import parse_suppressions, apply_suppressions, load_suppressions
from kubeflight.cli import main


def ids(a): return {f.id for f in a.findings}


def run(manifests, baseline=None, **kw):
    return assess(parse_text(manifests), parse_text(baseline) if baseline else None, **kw)


def test_loadbalancer_without_source_ranges_is_high():
    a = run("apiVersion: v1\nkind: Service\nmetadata: {name: web}\nspec: {type: LoadBalancer, ports: [{port: 80}]}\n")
    f = next(f for f in a.findings if f.id == "KF-EXP-001")
    assert f.severity == "high"


def test_unchanged_exposure_not_reflagged_against_baseline():
    svc = "apiVersion: v1\nkind: Service\nmetadata: {name: web}\nspec: {type: NodePort, ports: [{port: 80}]}\n"
    assert "KF-EXP-001" not in ids(run(svc, baseline=svc))
    assert "KF-EXP-001" in ids(run(svc))


def test_ingress_without_tls_and_external_ips():
    a = run("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: i}\nspec: {rules: []}\n---\n"
            "apiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec: {externalIPs: ['1.2.3.4'], ports: [{port: 80}]}\n")
    assert {"KF-EXP-002", "KF-EXP-003"} <= ids(a)


def test_rbac_wildcard_cluster_admin_and_anonymous():
    a = run("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: wide}\nrules:\n  - apiGroups: ['']\n    resources: ['*']\n    verbs: [get]\n---\n"
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: b}\nroleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}\n"
            "subjects:\n  - {kind: User, name: system:anonymous}\n")
    assert {"KF-RBAC-020", "KF-RBAC-021", "KF-RBAC-022"} <= ids(a)
    assert a.decision == "DO NOT DEPLOY"


def test_pvc_shrink_needs_baseline():
    pvc = lambda size: f"apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {{name: d}}\nspec:\n  resources:\n    requests: {{storage: {size}}}\n"
    assert "KF-STO-010" in ids(run(pvc("50Gi"), baseline=pvc("100Gi")))
    assert "KF-STO-010" not in ids(run(pvc("100Gi"), baseline=pvc("50Gi")))
    assert "KF-STO-010" not in ids(run(pvc("50Gi")))


def test_hpa_bounds():
    hpa = lambda lo, hi: f"apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata: {{name: h}}\nspec: {{minReplicas: {lo}, maxReplicas: {hi}}}\n"
    assert "KF-REL-020" in ids(run(hpa(5, 2)))
    assert "KF-REL-021" in ids(run(hpa(3, 3)))
    assert not ({"KF-REL-020", "KF-REL-021"} & ids(run(hpa(2, 5))))


SVC = "apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: prod}\nspec: {type: LoadBalancer, ports: [{port: 80}]}\n"


def test_suppression_hides_finding_and_is_reported():
    sups = parse_suppressions({"ignore": [{"id": "KF-EXP-001", "resource": "Service/prod/*", "reason": "public site", "expires": "2999-01-01"}]})
    a = run(SVC, suppressions=sups)
    assert "KF-EXP-001" not in ids(a)
    assert a.to_dict()["suppressed"][0]["reason"] == "public site"


def test_expired_suppression_keeps_finding_and_adds_note():
    sups = parse_suppressions({"ignore": [{"id": "KF-EXP-001", "reason": "temp", "expires": "2001-01-01"}]})
    a = run(SVC, suppressions=sups)
    assert {"KF-EXP-001", "KF-SUP-900"} <= ids(a)


def test_critical_suppression_requires_expiry():
    sups = parse_suppressions({"ignore": [{"id": "KF-RBAC-021", "reason": "legacy"}]})
    crit = [f for f in run("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: b}\nroleRef: {name: cluster-admin}\nsubjects: []\n").findings if f.id == "KF-RBAC-021"]
    kept, suppressed, notes = apply_suppressions(crit, sups, dt.date(2026, 1, 1))
    assert kept and not suppressed and notes[0].id == "KF-SUP-901"


@pytest.mark.parametrize("doc", [
    {"ignore": [{"reason": "x"}]}, {"ignore": [{"id": "KF-EXP-001"}]},
    {"ignore": [{"id": "nope", "reason": "x"}]}, {"ignore": "x"},
    {"ignore": [{"id": "KF-EXP-001", "reason": "x", "expires": "tomorrow"}]},
])
def test_invalid_ignore_documents_rejected(doc):
    with pytest.raises(ValueError):
        parse_suppressions(doc)


def test_cli_ignore_file_and_fail_on_medium(tmp_path, capsys):
    m = tmp_path / "m.yaml"; m.write_text(SVC)
    ig = tmp_path / "ignore.yaml"; ig.write_text("ignore:\n  - {id: KF-EXP-001, reason: public, expires: 2999-01-01}\n")
    assert main(["check", str(m), "--fail-on", "high"]) == 3
    assert main(["check", str(m), "--fail-on", "high", "--ignore-file", str(ig)]) == 0
    bad = tmp_path / "bad.yaml"; bad.write_text("ignore: [")
    assert main(["check", str(m), "--ignore-file", str(bad)]) == 2
    assert main(["check", str(m), "--ignore-file", str(tmp_path / "missing.yaml")]) == 2
    low = tmp_path / "low.yaml"; low.write_text("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec:\n  replicas: 3\n  selector: {matchLabels: {a: b}}\n  template:\n    metadata: {labels: {a: b}}\n    spec: {containers: [{name: c, image: 'x:1'}]}\n")
    assert main(["check", str(low), "--fail-on", "low", "--format", "json", "--output", str(tmp_path / "o.json")]) == 3


def test_api_accepts_suppressions():
    from fastapi.testclient import TestClient
    from kubeflight.server import app
    c = TestClient(app)
    r = c.post("/api/check", json={"manifests": SVC, "suppressions": [{"id": "KF-EXP-001", "reason": "public", "expires": "2999-01-01"}]})
    assert r.status_code == 200 and "KF-EXP-001" not in {f["id"] for f in r.json()["findings"]}
    assert c.post("/api/check", json={"manifests": SVC, "suppressions": [{"id": "KF-EXP-001"}]}).status_code == 400


def test_markdown_report_escapes_untrusted_names():
    from kubeflight.report import markdown_report
    a = run("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: 'x|<b>`y'}\nspec:\n  selector: {matchLabels: {a: b}}\n  template:\n    metadata: {labels: {a: b}}\n    spec: {containers: [{name: 'c|<i>', image: 'x:latest'}]}\n")
    md = markdown_report(a)
    assert "<b>" not in md and "<i>" not in md
    for line in md.splitlines():
        if line.startswith("| ") and "KF-" not in line and "SUP" not in line and "Unpinned" in line:
            assert line.count("|") - line.count("\\|") == 5  # 4 columns -> 5 unescaped separators
