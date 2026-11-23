# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import json
import re
from pathlib import Path
from kubeflight.cli import main
from kubeflight.engine import assess
from kubeflight.parser import parse_text, load_path
from kubeflight.registry import REGISTRY, SEVERITIES, get_rule
from kubeflight.report import sarif_report, filter_min_severity

ROOT = Path(__file__).parents[1]


def run(text, **kw):
    return assess(parse_text(text), **kw)

def ids(a): return {f.id for f in a.findings}

def find(a, fid): return [f for f in a.findings if f.id == fid]

def deploy(name="web", replicas=1, pod_extra="", spec_extra="", container_extra="", ns="default", labels="app: web"):
    return f"""apiVersion: apps/v1
kind: Deployment
metadata: {{name: {name}, namespace: {ns}}}
spec:
  replicas: {replicas}
{spec_extra}
  selector: {{matchLabels: {{{labels}}}}}
  template:
    metadata: {{labels: {{{labels}}}}}
    spec:
{pod_extra}
      containers:
      - name: c
        image: nginx:1.27
{container_extra}
"""

# ---- registry -------------------------------------------------------------

def test_every_emitted_id_is_registered():
    src = "".join(p.read_text() for p in (ROOT / "kubeflight").glob("*.py") if p.name != "registry.py")
    literal = set(re.findall(r'"(KF-[A-Z]+-\d+)"', src))
    assert literal and not (literal - set(REGISTRY)), literal - set(REGISTRY)

def test_examples_only_emit_registered_ids():
    for ex in ("demo/app.yaml", "unsafe/unsafe.yaml"):
        a = assess(load_path(ROOT / "examples" / ex))
        assert ids(a) <= set(REGISTRY)

def test_registry_entries_are_complete():
    for r in REGISTRY.values():
        assert r.severity in SEVERITIES and r.title and r.category and r.rationale and r.fix, r.id
        assert re.fullmatch(r"KF-[A-Z]+-\d{3}", r.id)

def test_explain_command(capsys):
    assert main(["explain", "kf-sec-030"]) == 0
    out = capsys.readouterr().out
    assert "KF-SEC-030" in out and "How to fix" in out
    assert main(["explain", "KF-SEC-031", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == "KF-SEC-031"
    assert main(["explain", "KF-NOPE-999"]) == 2
    assert main(["explain", "--list"]) == 0 and "KF-NET-020" in capsys.readouterr().out
    assert main(["explain"]) == 2

def test_min_severity_filters_output(tmp_path):
    out = tmp_path / "r.json"
    assert main(["check", str(ROOT / "examples/unsafe/unsafe.yaml"), "--format", "json", "--min-severity", "high", "--fail-on", "never", "--output", str(out)]) == 0
    d = json.loads(out.read_text())
    assert d["findings"] and {f["severity"] for f in d["findings"]} <= {"high", "critical"}
    assert d["summary"]["low"] == 0 and d["decision"] == "DO NOT DEPLOY"
    full = assess(load_path(ROOT / "examples/unsafe/unsafe.yaml"))
    assert filter_min_severity(full, "info") is full and len(full.findings) > len(d["findings"])

# ---- pod security extras --------------------------------------------------

def test_automount_default_sa():
    assert "KF-SEC-030" in ids(run(deploy()))
    assert "KF-SEC-030" not in ids(run(deploy(pod_extra="      automountServiceAccountToken: false")))
    sa = "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: default}\nautomountServiceAccountToken: false\n"
    assert "KF-SEC-030" not in ids(run(deploy() + "---\n" + sa))

def test_hostport_and_privileged_port():
    a = run(deploy(container_extra="        ports: [{containerPort: 80, hostPort: 8080}]"))
    assert find(a, "KF-SEC-031")[0].severity == "high" and "KF-SEC-032" in ids(a)
    ok = run(deploy(container_extra="        ports: [{containerPort: 80}]\n        securityContext: {capabilities: {add: [NET_BIND_SERVICE]}}"))
    assert "KF-SEC-032" not in ids(ok)
    ok2 = run(deploy(pod_extra="      securityContext: {sysctls: [{name: net.ipv4.ip_unprivileged_port_start, value: '0'}]}",
                     container_extra="        ports: [{containerPort: 80}]"))
    assert "KF-SEC-032" not in ids(ok2)
    assert "KF-SEC-032" not in ids(run(deploy(container_extra="        ports: [{containerPort: 8080}]")))

def test_non_numeric_uid_does_not_crash():
    run(deploy(container_extra="        securityContext: {runAsUser: abc}"))

# ---- reliability ----------------------------------------------------------

SVC = "---\napiVersion: v1\nkind: Service\nmetadata: {name: web}\nspec: {selector: {app: web}, ports: [{port: 80}]}\n"

def test_best_effort_and_limit_below_request():
    assert "KF-REL-005" in ids(run(deploy()))
    ok = run(deploy(container_extra="        resources: {requests: {cpu: 100m, memory: 64Mi}, limits: {memory: 128Mi}}"))
    assert "KF-REL-005" not in ids(ok) and "KF-REL-006" not in ids(ok)
    bad = run(deploy(container_extra="        resources: {requests: {cpu: 500m, memory: 64Mi}, limits: {cpu: 100m, memory: 128Mi}}"))
    assert [f.title for f in find(bad, "KF-REL-006")] == ["cpu limit below request: c"]

def test_jobs_are_not_flagged_for_probes():
    job = "apiVersion: batch/v1\nkind: Job\nmetadata: {name: j}\nspec:\n  template:\n    spec:\n      restartPolicy: Never\n      containers: [{name: c, image: 'busybox:1.36'}]\n"
    a = run(job)
    assert not ({"KF-REL-003", "KF-REL-004"} & ids(a))
    assert "KF-REL-003" in ids(run(deploy()))

def test_single_replica_behind_service():
    assert "KF-REL-010" in ids(run(deploy(replicas=1) + SVC))
    assert "KF-REL-010" not in ids(run(deploy(replicas=1)))
    assert "KF-REL-010" not in ids(run(deploy(replicas=2) + SVC))
    hpa = "---\napiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata: {name: web}\nspec: {scaleTargetRef: {kind: Deployment, name: web}, minReplicas: 2, maxReplicas: 5}\n"
    assert "KF-REL-010" not in ids(run(deploy(replicas=1) + SVC + hpa))

def test_replicas_zero_is_not_treated_as_one():
    a = run(deploy(replicas=0) + SVC)
    assert "KF-REL-010" not in ids(a)

def pdb(extra): return f"---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata: {{name: web}}\nspec:\n  selector: {{matchLabels: {{app: web}}}}\n  {extra}\n"

def test_pdb_blocking_drains():
    f = find(run(deploy(replicas=3) + pdb("minAvailable: 3")), "KF-REL-011")
    assert f and f[0].resource == "PodDisruptionBudget/default/web"
    assert find(run(deploy(replicas=3) + pdb("minAvailable: '100%'")), "KF-REL-011")
    assert find(run(deploy(replicas=3) + pdb("maxUnavailable: 0")), "KF-REL-011")
    assert not find(run(deploy(replicas=3) + pdb("minAvailable: 2")), "KF-REL-011")
    assert not find(run(deploy(replicas=3) + pdb("maxUnavailable: 1")), "KF-REL-011")

def test_rolling_update_zero_zero():
    bad = "  strategy: {type: RollingUpdate, rollingUpdate: {maxUnavailable: 0, maxSurge: '0%'}}"
    f = find(run(deploy(spec_extra=bad)), "KF-REL-012")
    assert f and f[0].severity == "critical"
    assert not find(run(deploy(spec_extra="  strategy: {rollingUpdate: {maxUnavailable: 0, maxSurge: 1}}")), "KF-REL-012")
    assert not find(run(deploy()), "KF-REL-012")

# ---- networkpolicy --------------------------------------------------------

def np(body, name="p", ns="default"):
    return f"---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {{name: {name}, namespace: {ns}}}\nspec:\n{body}\n"

DENY = np("  podSelector: {}\n  policyTypes: [Ingress, Egress]", "deny")

def test_default_deny_gaps():
    a = run(deploy())
    assert {"KF-NET-010", "KF-NET-011"} <= ids(a)
    b = run(deploy() + DENY)
    assert not ({"KF-NET-010", "KF-NET-011", "KF-NET-012"} & ids(b))
    only_in = run(deploy() + np("  podSelector: {}\n  policyTypes: [Ingress]"))
    assert "KF-NET-010" not in ids(only_in) and "KF-NET-011" in ids(only_in)
    # default policyTypes always include Ingress, even with no ingress key
    assert "KF-NET-010" not in ids(run(deploy() + np("  podSelector: {}")))
    # allow-all ingress is not a default deny
    assert "KF-NET-010" in ids(run(deploy() + np("  podSelector: {}\n  policyTypes: [Ingress]\n  ingress: [{}]")))

def test_workload_not_selected():
    other = np("  podSelector: {matchLabels: {app: other}}\n  policyTypes: [Ingress]\n  ingress: [{from: [{podSelector: {}}]}]")
    assert "KF-NET-012" in ids(run(deploy() + other))
    assert "KF-NET-012" not in ids(run(deploy()))

def test_wide_egress_and_ipblocks():
    eg = np("  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n  - to: [{ipBlock: {cidr: 0.0.0.0/0, except: [10.0.0.0/8]}}]")
    assert find(run(deploy() + eg), "KF-NET-020")
    v6 = np("  podSelector: {}\n  policyTypes: [Egress]\n  egress: [{to: [{ipBlock: {cidr: '::/0'}}]}]")
    assert find(run(deploy() + v6), "KF-NET-020")
    empty = np("  podSelector: {}\n  policyTypes: [Egress]\n  egress: [{}]")
    assert find(run(deploy() + empty), "KF-NET-020")
    wide = np("  podSelector: {}\n  policyTypes: [Egress]\n  egress: [{to: [{ipBlock: {cidr: 10.0.0.0/7}}]}]")
    a = run(deploy() + wide)
    assert find(a, "KF-NET-022") and not find(a, "KF-NET-020")
    narrow = np("  podSelector: {}\n  policyTypes: [Egress]\n  egress: [{to: [{ipBlock: {cidr: 10.1.0.0/16}}]}]")
    assert not ({"KF-NET-020", "KF-NET-022"} & ids(run(deploy() + narrow)))
    ing = np("  podSelector: {}\n  ingress: [{from: [{ipBlock: {cidr: 0.0.0.0/0}}]}]")
    assert find(run(deploy() + ing), "KF-NET-021")

def test_allow_all_ingress_peers():
    for body in ("  ingress: [{}]", "  ingress: [{from: [{}]}]", "  ingress: [{from: [{namespaceSelector: {}}]}]",
                 "  ingress: [{from: [], ports: [{port: 80}]}]"):
        assert find(run(deploy() + np("  podSelector: {}\n" + body)), "KF-NET-030"), body
    ok = np("  podSelector: {}\n  ingress: [{from: [{namespaceSelector: {matchLabels: {team: a}}}]}]")
    assert not find(run(deploy() + ok), "KF-NET-030")

def test_empty_from_allows_path_in_engine():
    # `from: []` matches all sources, so it must not be reported as a blocked path (KF-NET-001).
    text = """apiVersion: apps/v1
kind: Deployment
metadata: {name: client}
spec:
  selector: {matchLabels: {app: client}}
  template:
    metadata: {labels: {app: client}, annotations: {kubeflight.io/depends-on: "web"}}
    spec: {containers: [{name: c, image: 'x:1'}]}
---
""" + deploy() + SVC
    base = run(text + np("  podSelector: {matchLabels: {app: web}}\n  policyTypes: [Ingress]\n  ingress: [{from: [{podSelector: {matchLabels: {app: nobody}}}]}]"))
    allowed = run(text + np("  podSelector: {matchLabels: {app: web}}\n  policyTypes: [Ingress]\n  ingress: [{from: []}]"))
    assert "KF-NET-001" not in ids(allowed)
    assert "KF-NET-001" in ids(base)  # sanity: the scenario does produce a blocked path

# ---- sarif / locations ------------------------------------------------------

def test_sarif_rules_and_locations(tmp_path, monkeypatch):
    f = tmp_path / "app.yaml"
    f.write_text("# header\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n---\n" + deploy())
    monkeypatch.chdir(tmp_path)
    a = assess(load_path(f))
    s = json.loads(sarif_report(a))
    run0 = s["runs"][0]
    rule = next(r for r in run0["tool"]["driver"]["rules"] if r["id"] == "KF-SEC-030")
    assert rule["help"]["text"] and rule["help"]["markdown"] and rule["properties"]["security-severity"] == "3.0"
    assert rule["helpUri"].startswith("https://")
    res = next(r for r in run0["results"] if r["ruleId"] == "KF-SEC-030")
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.yaml" and loc["region"]["startLine"] == 7
    assert run0["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == "KF-SEC-030"
    ns = next(r for r in run0["results"] if r["ruleId"] == "KF-NET-010")
    assert "physicalLocation" not in ns["locations"][0] and ns["locations"][0]["logicalLocations"]

def test_parser_locations_list_and_baseline_equality():
    objs = parse_text("apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: ConfigMap, metadata: {name: a}}\n- {apiVersion: v1, kind: ConfigMap, metadata: {name: b}}\n", "f.yaml")
    assert [o.source_line for o in objs] == [4, 5] and objs[0] == {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "a"}}
    assert parse_text("a: 1\n", "input")[0].source_file is None
    assert json.dumps(objs[0])
