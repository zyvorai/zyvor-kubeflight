import json
import pytest
from kubeflight.apis import api_findings, parse_version
from kubeflight.fields import field_findings
from kubeflight.cli import main
from kubeflight.parser import load_path, parse_text

def F(yaml_text): return field_findings(parse_text(yaml_text))

DEP = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: w, labels: {app: w}}
spec:
  replicas: 2
  selector: {matchLabels: {app: w}}
  template:
    metadata: {labels: {app: w}}
    spec:
      containers:
        - name: a
          image: x:1
          ports: [{containerPort: 80, name: http}]
          env: [{name: A, value: "1"}]
          resources: {requests: {cpu: 100m, memory: 64Mi}, limits: {cpu: 1, memory: 128Mi}}
          securityContext: {runAsNonRoot: true, capabilities: {drop: [ALL]}}
"""

def test_clean_manifest_has_no_findings():
    assert F(DEP) == []

def test_unknown_field_with_suggestion():
    fs = F(DEP.replace("replicas: 2", "replica: 2"))
    assert [f.id for f in fs] == ["KF-FLD-001"]
    assert "spec.replica" in fs[0].evidence and "'replicas'" in fs[0].evidence

def test_nested_and_list_paths():
    fs = F(DEP.replace("containerPort", "containerport").replace("runAsNonRoot", "runAsNonroot"))
    ev = " | ".join(f.evidence for f in fs)
    assert "containers[0].ports[0].containerport" in ev and "securityContext.runAsNonroot" in ev

def test_wrong_types():
    fs = F(DEP.replace('value: "1"', "value: 1").replace("replicas: 2", 'replicas: "2"'))
    assert {f.id for f in fs} == {"KF-FLD-002"}
    assert any("spec.replicas" in f.evidence for f in fs) and any("quote the value" in f.evidence for f in fs)

def test_bool_is_not_int_and_numbers_are_valid_quantities():
    assert F(DEP.replace("replicas: 2", "replicas: true"))[0].id == "KF-FLD-002"
    assert F(DEP.replace("memory: 64Mi", "memory: 67108864")) == []

def test_configmap_numeric_value():
    fs = F("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata: {n: 3, ok: 'x'}\n")
    assert [f.id for f in fs] == ["KF-FLD-002"] and "data.n" in fs[0].evidence

def test_null_and_any_fields_are_tolerated():
    assert F(DEP.replace("replicas: 2", "replicas:")) == []
    assert F(DEP.replace("image: x:1", "image: x:1\n          lifecycle: {whatever: [1]}\n          livenessProbe: {httpGet: {path: /, port: 80}, periodSeconds: 5}")) == []

def test_unknown_kinds_and_foreign_groups_skipped():
    assert F("apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata: {name: k}\nspec: {anything: 1}\n") == []
    assert F("apiVersion: example.com/v1\nkind: Widget\nmetadata: {name: k}\nspec: {anything: 1}\n") == []

def test_wrong_container_shapes():
    fs = F(DEP.replace("containers:\n        - name: a", "containers:\n        - name: a\n          args: foo\n        - name: b").replace("ports: [{containerPort: 80, name: http}]", "ports: {a: 1}"))
    assert {f.id for f in fs} == {"KF-FLD-002"}

def test_other_kinds_smoke():
    ok = """
apiVersion: v1
kind: Service
metadata: {name: s}
spec: {ports: [{port: 80, targetPort: http}], selector: {a: b}, type: ClusterIP}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: i}
spec: {tls: [{hosts: [a], secretName: s}], rules: [{host: a}]}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: c}
spec: {schedule: "* * * * *", jobTemplate: {spec: {template: {spec: {restartPolicy: Never, containers: [{name: a, image: b}]}}}}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: r}
subjects: [{kind: User, name: u, apiGroup: rbac.authorization.k8s.io}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: x}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: h}
spec: {scaleTargetRef: {kind: Deployment, name: w}, minReplicas: 1, maxReplicas: 3}
---
apiVersion: v1
kind: Secret
metadata: {name: s}
stringData: {a: b}
"""
    assert F(ok) == []
    bad = F(ok.replace("targetPort: http", "target_port: http").replace("jobTemplate", "jobtemplate"))
    assert len(bad) == 2

def test_issue_cap_per_resource():
    many = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata: {" + ", ".join(f"k{i}: {i}" for i in range(100)) + "}\n"
    fs = F(many)
    assert len(fs) == 21 and fs[-1].severity == "info"

def test_hostile_deep_manifest_does_not_crash():
    deep = cur = {}
    for _ in range(3000):
        cur["a"] = {}; cur = cur["a"]
    fs = field_findings([{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x"}, "data": deep}])
    assert fs and fs[0].id == "KF-FLD-002"

def test_repo_deploy_manifests_have_no_field_findings():
    res = load_path("deploy/kubernetes")
    assert field_findings(res) == []

# ---- API table
def R(api, kind): return [{"apiVersion": api, "kind": kind, "metadata": {"name": "x"}}]

def test_version_parsing():
    assert parse_version("1.31") == (1, 31) == parse_version("v1.31.4") == parse_version("1.31.0-gke.1")
    for bad in ("", "1", "latest", "1.x", "one.two"):
        with pytest.raises(ValueError):
            parse_version(bad)

@pytest.mark.parametrize("target,api,kind,expected", [
    ("1.24", "batch/v1beta1", "CronJob", "KF-UPG-011"),     # deprecated 1.21, removed 1.25
    ("1.25", "batch/v1beta1", "CronJob", "KF-UPG-010"),
    ("1.20", "batch/v1beta1", "CronJob", None),             # not yet deprecated
    ("1.21", "batch/v1beta1", "CronJob", "KF-UPG-011"),
    ("1.22", "extensions/v1beta1", "Ingress", "KF-UPG-010"),
    ("1.21", "extensions/v1beta1", "Ingress", "KF-UPG-011"),
    ("1.15", "extensions/v1beta1", "Deployment", "KF-UPG-011"),
    ("1.16", "extensions/v1beta1", "Deployment", "KF-UPG-010"),
    ("1.28", "autoscaling/v2beta2", "HorizontalPodAutoscaler", "KF-UPG-010"),
    ("1.25", "autoscaling/v2beta2", "HorizontalPodAutoscaler", "KF-UPG-011"),
    ("1.31", "flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema", "KF-UPG-011"),
    ("1.32", "flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema", "KF-UPG-010"),
    ("1.37", "apps/v1", "Deployment", None),
    ("1.37", "extensions/v1beta1", "SomethingNew", "KF-UPG-010"),   # group-level fallback
    ("1.37", "v1", "Endpoints", "KF-UPG-011"),
    ("1.32", "v1", "Endpoints", None),
])
def test_removal_table_against_target(target, api, kind, expected):
    fs = api_findings(R(api, kind), target)
    assert [f.id for f in fs] == ([expected] if expected else [])

def test_severities_and_replacement_text():
    f = api_findings(R("policy/v1beta1", "PodDisruptionBudget"), "1.30")[0]
    assert f.severity == "critical" and "policy/v1" in f.recommendation and "1.25" in f.evidence
    assert api_findings(R("v1", "Endpoints"), "1.37")[0].severity == "low"

def test_table_is_internally_consistent():
    from kubeflight.apis import TABLE
    for key, (dep, rem, repl) in TABLE.items():
        assert rem is None or rem > dep, key
        assert repl

def test_malformed_resources_ignored():
    assert api_findings([{"apiVersion": 3, "kind": "x"}, {"kind": "Pod"}, "str"], "1.30") == []

# ---- CLI integration
def run(argv, capsys):
    rc = main(argv); return rc, capsys.readouterr()

def test_cli_target_kubernetes_changes_verdict(capsys):
    rc, out = run(["check", "examples/typos/typos.yaml", "--format", "json", "--fail-on", "never", "--target-kubernetes", "1.24"], capsys)
    ids = [f["id"] for f in json.loads(out.out)["findings"]]
    assert "KF-UPG-011" in ids and "KF-UPG-010" not in ids
    rc, out = run(["check", "examples/typos/typos.yaml", "--format", "json", "--fail-on", "never", "--target-kubernetes", "1.30"], capsys)
    d = json.loads(out.out)
    assert d["target_kubernetes"] == "1.30"
    assert [f["id"] for f in d["findings"]].count("KF-UPG-010") == 1

def test_cli_old_coarse_finding_deduplicated(capsys):
    _, out = run(["check", "examples/unsafe/unsafe.yaml", "--format", "json", "--fail-on", "never"], capsys)
    fs = json.loads(out.out)["findings"]
    for f in fs:
        if f["id"] == "KF-UPG-001":
            assert not any(g["id"] == "KF-UPG-010" and g["resource"] == f["resource"] for g in fs)

def test_cli_typos_example_and_opt_out(capsys):
    _, out = run(["check", "examples/typos/typos.yaml", "--format", "json", "--fail-on", "never"], capsys)
    ids = [f["id"] for f in json.loads(out.out)["findings"]]
    assert ids.count("KF-FLD-001") == 2 and ids.count("KF-FLD-002") == 2
    _, out = run(["check", "examples/typos/typos.yaml", "--format", "json", "--fail-on", "never", "--no-field-check"], capsys)
    assert not any(f["id"].startswith("KF-FLD") for f in json.loads(out.out)["findings"])

def test_cli_bad_target_exit_2(capsys):
    rc, out = run(["check", "examples/demo/app.yaml", "--target-kubernetes", "soon"], capsys)
    assert rc == 2 and "invalid Kubernetes version" in out.err

def test_demo_stays_clean_of_new_findings(capsys):
    _, out = run(["check", "examples/demo/app.yaml", "--format", "json", "--fail-on", "never"], capsys)
    assert not [f for f in json.loads(out.out)["findings"] if f["id"].startswith(("KF-FLD", "KF-UPG", "KF-CUS"))]
