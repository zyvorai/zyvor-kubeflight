import json, time
import pytest
from kubeflight.cli import main
from kubeflight.rules import (RuleError, evaluate, parse_rules, load_rules, run_rule_tests, rule_findings, check_regex, MAX_STEPS)

DEP = {"kind": "Deployment", "apiVersion": "apps/v1", "metadata": {"name": "w", "namespace": "prod", "labels": {"app.kubernetes.io/name": "w"}},
       "spec": {"replicas": 3, "template": {"spec": {"containers": [
           {"name": "a", "image": "r/a:1", "resources": {"limits": {"memory": "1Gi", "cpu": "500m"}}},
           {"name": "b", "image": "r/b:latest"}]}}}}

def ev(src, res=DEP): return evaluate(src, res)

def test_paths_and_literals():
    assert ev("spec.replicas") == 3
    assert ev("spec.nothing.here") is None
    assert ev('metadata.labels["app.kubernetes.io/name"]') == "w"
    assert ev("spec.template.spec.containers[0].name") == "a"
    assert ev("spec.template.spec.containers[-1].name") == "b"
    assert ev("spec.template.spec.containers[*].name") == ["a", "b"]
    assert ev("containers[*].image") == ["r/a:1", "r/b:latest"]
    assert ev("pod.containers[1].name") == "b"
    assert ev("[1, 2, 3]") == [1, 2, 3]

def test_operators():
    assert ev("spec.replicas >= 2 and spec.replicas < 4")
    assert ev("not spec.replicas == 1")
    assert ev('kind in ["Deployment", "StatefulSet"]')
    assert ev('kind not in ["Pod"]')
    assert ev('"prod" in metadata.namespace')
    assert ev("spec.replicas != null")
    assert not ev("spec.missing >= 1")           # null ordering is false, not an error
    assert not ev('spec.replicas == "3"')         # no coercion
    assert ev("true == true") and not ev("1 == true")

def test_quantifiers_and_functions():
    assert not ev("all c in containers: exists(c.resources.limits.memory)")
    assert ev("any c in containers: exists(c.resources.limits.memory)")
    assert ev("all c in spec.nothing: false")     # vacuous
    assert ev('any c in containers: endswith(c.image, ":latest")')
    assert ev('mem(containers[0].resources.limits.memory) == mem("1024Mi")')
    assert ev('cpu(containers[0].resources.limits.cpu) == 500')
    assert ev("len(containers) == 2") and ev("len(spec.nothing) == 0")
    assert ev("keys(metadata.labels) == ['app.kubernetes.io/name']")
    assert ev('lower("AbC") == "abc"') and ev('upper(null) == null')
    assert ev('glob(containers[0].image, "r/*:1")')
    assert ev('regex(containers[0].image, "^r/[a-z]+:[0-9]$")')
    assert ev('default(spec.nothing, 7) == 7')

@pytest.mark.parametrize("src", [
    "spec.replicas ==", "1 +", "foo(", "nosuchfn(1)", "len()", "a b", "[1,", "x[", "x[foo]", ")", "all c containers: true",
    "'unterminated", "spec.replicas @ 1", "", "   ", "all c in containers true", "kind in", "not",
])
def test_syntax_errors(src):
    with pytest.raises(RuleError):
        evaluate(src, DEP)

@pytest.mark.parametrize("src", ["1 and true", "not 1", "all c in 5: true", "all c in containers: 1", "len(5)", "regex(5, 'a')", "mem('bogus')", "keys(5)"])
def test_type_errors_are_ruleerrors(src):
    with pytest.raises(RuleError):
        evaluate(src, DEP)

def test_no_python_eval_surface():
    for src in ["__import__('os').system('true')", "().__class__", "open('/etc/passwd')", "exec('1')", "eval('1')", "lambda: 1"]:
        with pytest.raises(RuleError):
            evaluate(src, DEP)
    # dunder-looking path segments are just missing keys, never attribute access
    assert ev("metadata.__class__") is None

# ---- hostile input
def test_deep_nesting_rejected_without_recursion_error():
    with pytest.raises(RuleError, match="nesting"):
        evaluate("(" * 30 + "true" + ")" * 30, DEP)
    with pytest.raises(RuleError, match="nesting"):
        evaluate("not " * 30 + "true", DEP)
    with pytest.raises(RuleError):
        evaluate("[" * 30 + "]" * 30, DEP)

def test_long_expression_and_token_limits():
    with pytest.raises(RuleError, match="longer"):
        evaluate("1 == 1 " + "and true " * 200, DEP)
    with pytest.raises(RuleError, match="tokens"):
        evaluate("[" + ",".join(["1"] * 200) + "]", DEP)       # 400 tokens, under 500 chars? uses commas
    with pytest.raises(RuleError):
        evaluate("'" + "a" * 300 + "'", DEP)

def test_huge_resource_hits_step_budget():
    big = {"kind": "Pod", "spec": {"containers": [{"name": str(i), "image": "x"} for i in range(30000)]}}
    t = time.time()
    with pytest.raises(RuleError, match="steps"):
        evaluate("all c in containers: c.image == 'x'", big)
    assert time.time() - t < 5
    with pytest.raises(RuleError, match="steps"):
        evaluate("any a in containers: any b in containers: a.name == b.image", big)

def test_nested_quantifier_blowup_bounded():
    res = {"kind": "Pod", "spec": {"containers": [{"name": str(i)} for i in range(400)]}}
    t = time.time()
    with pytest.raises(RuleError, match="steps"):
        evaluate("all a in containers: all b in containers: all c in containers: a.name != b.name or true", res)
    assert time.time() - t < 5

def test_deeply_nested_manifest_is_handled():
    deep = cur = {}
    for _ in range(5000):
        cur["a"] = {}; cur = cur["a"]
    assert evaluate("exists(a.a.a)", {"kind": "X", "a": deep}) is True   # iterative path walk

@pytest.mark.parametrize("pat", ["(a+)+$", "(a*)*b", "(a|aa)+$", "a*a*a*a*b", r"(a)\1", "(?=a)b", "(?i)a", "(a+){2}", "x" * 101, "a{1,1000}", r"\g<1>"])
def test_regex_dos_patterns_rejected(pat):
    with pytest.raises(RuleError):
        check_regex(pat)
    with pytest.raises(RuleError):   # also rejected when reached through an expression at runtime
        evaluate("regex('a' , p)", {"p": pat})

@pytest.mark.parametrize("pat", ["^r/[a-z]+:[0-9]+$", r"^\d{1,3}\.\d{1,3}$", "a|b|c", "(foo|bar)baz", "[^]a]+", r"\(literal\)+"])
def test_regex_safe_patterns_allowed(pat):
    check_regex(pat)

def test_regex_subject_cap_and_runtime_speed():
    with pytest.raises(RuleError, match="subject"):
        evaluate("regex(s, 'a')", {"s": "a" * 1000})
    t = time.time()
    evaluate("regex(s, 'a*a*a*b')", {"s": "a" * 256})      # worst allowed shape is bounded
    assert time.time() - t < 3

def test_glob_complexity_cap():
    with pytest.raises(RuleError):
        evaluate("glob('aaaa', '*a*a*a*a*b')", DEP)

# ---- rule files
GOOD = """
rules:
  - id: KF-CUS-001
    title: replicas
    severity: high
    kinds: [Deployment]
    assert: 'spec.replicas >= 2'
    tests:
      - {name: ok, expect: pass, resource: {kind: Deployment, spec: {replicas: 2}}}
      - {name: bad, expect: fail, resource: {kind: Deployment, spec: {replicas: 1}}}
      - {name: err, expect: error, resource: {kind: Deployment, spec: {replicas: 1}}}
"""

def test_rule_file_parses_and_runs_findings():
    rules = parse_rules(GOOD)
    fs = rule_findings([{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"replicas": 1}}, {"kind": "Service", "metadata": {"name": "s"}}], rules)
    assert [(f.id, f.severity, f.category) for f in fs] == [("KF-CUS-001", "high", "custom")]
    assert "spec.replicas >= 2" in fs[0].evidence

def test_runtime_error_becomes_cus900_finding_not_crash():
    rules = parse_rules("rules:\n  - {id: KF-CUS-005, title: t, assert: 'len(spec.replicas) > 0'}\n")
    fs = rule_findings([{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"replicas": 1}}], rules)
    assert fs[0].id == "KF-CUS-900" and "len()" in fs[0].evidence

def test_non_boolean_assert_is_error():
    rules = parse_rules("rules:\n  - {id: KF-CUS-005, title: t, assert: 'spec.replicas'}\n")
    assert rule_findings([{"kind": "D", "metadata": {"name": "x"}, "spec": {"replicas": 1}}], rules)[0].id == "KF-CUS-900"

@pytest.mark.parametrize("text,frag", [
    ("rules: 5", "rules"), ("- a", "rules"), ("rules: [5]", "mapping"),
    ("rules: [{title: t, assert: 'true'}]", "KF-CUS"),
    ("rules: [{id: KF-CUS-900, title: t, assert: 'true'}]", "reserved"),
    ("rules: [{id: KF-X-001, title: t, assert: 'true'}]", "KF-CUS"),
    ("rules: [{id: KF-CUS-001, assert: 'true'}]", "title"),
    ("rules: [{id: KF-CUS-001, title: t}]", "assert"),
    ("rules: [{id: KF-CUS-001, title: t, assert: 'true', severity: urgent}]", "severity"),
    ("rules: [{id: KF-CUS-001, title: t, assert: 'true', asert: 1}]", "unknown key"),
    ("rules: [{id: KF-CUS-001, title: t, assert: 'a =='}]", "assert"),
    ("rules: [{id: KF-CUS-001, title: t, assert: 'true', kinds: Deployment}]", "kinds"),
    ("rules: [{id: KF-CUS-001, title: t, assert: 'true', tests: [{expect: maybe, resource: {}}]}]", "tests"),
    ("rules: [{id: KF-CUS-001, title: t, assert: 'true'}, {id: KF-CUS-001, title: t, assert: 'true'}]", "duplicate"),
    ("a: [", "YAML"),
])
def test_invalid_rule_files(text, frag):
    with pytest.raises(RuleError, match=frag):
        parse_rules(text)

def test_rule_file_limits():
    with pytest.raises(RuleError, match="larger"):
        parse_rules("rules: []\n#" + "x" * 300000)
    many = "rules:\n" + "".join(f"  - {{id: KF-CUS-{i + 1:04d}, title: t, assert: 'true'}}\n" for i in range(201))
    with pytest.raises(RuleError, match="more than"):
        parse_rules(many)
    with pytest.raises(RuleError):
        parse_rules("rules: " + "[" * 3000 + "]" * 3000)          # YAML bomb nesting

def test_yaml_anchor_bomb_is_bounded_by_size():
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nrules: []\n"
    with pytest.raises(RuleError):
        parse_rules(bomb)

def test_rule_tests_runner():
    res = run_rule_tests(parse_rules(GOOD))
    assert [(r["test"], r["ok"]) for r in res] == [("ok", True), ("bad", True), ("err", False)]
    assert "expected error but got" in res[2]["detail"]
    assert run_rule_tests(parse_rules("rules: [{id: KF-CUS-001, title: t, assert: 'true'}]"), require_tests=True)[0]["ok"] is False

def test_example_rules_file_passes_its_own_tests(capsys):
    assert main(["rules", "test", "examples/rules/custom-rules.yaml", "--require-tests"]) == 0
    assert "0 failed" in capsys.readouterr().out

def test_load_rules_missing_and_duplicate_across_files(tmp_path):
    with pytest.raises(RuleError, match="cannot read"):
        load_rules([tmp_path / "nope.yaml"])
    f = tmp_path / "a.yaml"; f.write_text(GOOD)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules([f, f])

# ---- CLI
def test_cli_check_with_rules(tmp_path, capsys):
    rc = main(["check", "examples/unsafe/unsafe.yaml", "--rules", "examples/rules/custom-rules.yaml", "--format", "json", "--fail-on", "never"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and any(f["id"] == "KF-CUS-001" for f in out["findings"])

def test_cli_rules_test_failure_and_bad_file(tmp_path, capsys):
    f = tmp_path / "r.yaml"; f.write_text(GOOD)
    assert main(["rules", "test", str(f)]) == 3
    assert "FAIL KF-CUS-001 err" in capsys.readouterr().out
    g = tmp_path / "bad.yaml"; g.write_text("rules: [{id: nope}]")
    assert main(["rules", "test", str(g)]) == 2
    assert main(["check", "examples/demo/app.yaml", "--rules", str(g)]) == 2

def test_suppression_applies_to_custom_findings(tmp_path, capsys):
    ign = tmp_path / "i.yaml"; ign.write_text("ignore:\n  - {id: KF-CUS-001, resource: '*', reason: accepted for now}\n")
    main(["check", "examples/unsafe/unsafe.yaml", "--rules", "examples/rules/custom-rules.yaml", "--ignore-file", str(ign), "--format", "json", "--fail-on", "never"])
    out = json.loads(capsys.readouterr().out)
    assert not any(f["id"] == "KF-CUS-001" for f in out["findings"]) and any(s["id"] == "KF-CUS-001" for s in out["suppressed"])

def test_api_rules_param():
    from fastapi.testclient import TestClient
    from kubeflight.server import app
    c = TestClient(app)
    body = {"manifests": json.dumps(DEP), "rules": GOOD.replace("spec.replicas >= 2", "spec.replicas >= 5")}
    r = c.post("/api/check", json=body)
    assert r.status_code == 200 and any(f["id"] == "KF-CUS-001" for f in r.json()["findings"])
    assert c.post("/api/check", json={**body, "rules": "rules: [{id: bad}]"}).status_code == 400
    assert c.post("/api/check", json={**body, "target_kubernetes": "nope"}).status_code == 400
