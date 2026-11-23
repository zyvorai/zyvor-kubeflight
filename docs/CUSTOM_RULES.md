---
hero:
  eyebrow: CUSTOM RULES
  title: Custom rules
---

Write your own checks in YAML. A rule says which resources it applies to and an expression that must be true; KubeFlight raises a finding (`KF-CUS-NNN`) for every resource where it is false.

```bash
kubeflight check app.yaml --rules rules.yaml        # repeat --rules for several files
kubeflight rules test rules.yaml --require-tests     # run the tests embedded in the file
```

The API accepts the same YAML in the `rules` field of `POST /api/check`. A bad rules file is a `400` there and exit code `2` on the CLI.

## Rule file

```yaml
rules:
  - id: KF-CUS-001                 # KF-CUS-001..899 or 1000+; 900-999 reserved
    title: Every container must set a memory limit
    severity: high                 # low | medium | high | critical (default medium)
    kinds: [Deployment, StatefulSet, Pod]   # optional; default: every kind
    match: 'pod != null'           # optional: skip resources where this is false
    assert: 'all c in containers: exists(c.resources.limits.memory)'
    message: optional evidence text          # default: "assertion is false: <assert>"
    recommendation: optional remediation text
    category: custom               # optional
    tests:                         # optional but encouraged
      - {name: ok, expect: pass, resource: {kind: Deployment, spec: {...}}}
```

Unknown keys are rejected (so `asert:` is an error, not a silently inactive rule). Suppressions (`--ignore-file`) work on `KF-CUS-*` like any other finding.

## Expression language

| Element | Syntax |
|---|---|
| Literals | `1`, `1.5`, `'text'`, `"text"`, `true`, `false`, `null`, `[1, 2]` |
| Paths | `spec.replicas`, `metadata.labels["app.kubernetes.io/name"]`, `spec.template.spec.containers[0].image`, `containers[*].image` |
| Missing values | A missing path is `null`; `[*]` yields a list of matches |
| Roots | Any top-level manifest field, plus `pod` (the pod spec of a workload) and `containers` (containers and initContainers) |
| Comparison | `==  !=  <  <=  >  >=  in  not in` |
| Logic | `and  or  not  ( )` (operands must be booleans) |
| Quantifiers | `all c in LIST: EXPR`, `any c in LIST: EXPR` (`all` over null/empty is true) |
| Functions | `len exists lower upper startswith endswith contains regex glob cpu mem keys default` |

`==` never coerces (`1 == "1"` is false, `1 == true` is false). Ordering compares number with number or string with string and is otherwise false, so a missing value fails `spec.replicas >= 2` rather than erroring. For Kubernetes quantities use `cpu(x)` (millicores) and `mem(x)` (bytes): `mem(c.resources.limits.memory) <= mem("4Gi")`.

Examples:

```yaml
assert: 'spec.replicas >= 2'
assert: 'not any c in containers: endswith(c.image, ":latest")'
assert: 'all c in containers: startswith(c.image, "registry.example.com/")'
assert: 'exists(metadata.labels["team"])'
assert: 'kind != "Service" or spec.type != "LoadBalancer"'
```

## Safety model

Rules come from files you may not fully control (shared repos, the API). There is no `eval`, `exec`, attribute access or import: the expression is tokenized and parsed by a small hand-written parser and run by a tree interpreter. A path segment such as `__class__` is just a dictionary key that is missing.

| Limit | Value |
|---|---|
| Rules file | 256 KiB, 200 rules, 20 tests per rule |
| Expression | 500 characters, 300 tokens, nesting depth 24, string literal 200 characters |
| Interpreter | 50,000 steps per rule and resource (bounds huge inputs and nested quantifiers) |
| `regex()` | Pattern up to 100 characters from a backtracking-safe subset: no `(?...)` groups or lookaround, no backreferences, no quantifier applied to a group (so no `(a+)+`), at most 3 quantifiers, repetition bounds up to 100; subject at most 256 characters |
| `glob()` | Pattern up to 100 characters, at most 3 `*` |

When a rule cannot be evaluated against a resource (type error, step budget, regex rejected), the run does not abort: a `KF-CUS-900` finding names the rule and the reason, so a broken rule is visible rather than silently passing.

Limits are not a security boundary against an attacker who can already run KubeFlight with arbitrary privileges; they keep honest mistakes and hostile-but-unprivileged inputs (huge manifests, ReDoS patterns, deep nesting) from hanging or crashing a run or the API worker.

## Testing rules

`tests` entries give an inline `resource` and an `expect`:

| expect | Meaning |
|---|---|
| `pass` | Rule applies and the assertion holds |
| `fail` | Rule applies and raises a finding |
| `skip` | `kinds`/`match` exclude the resource |
| `error` | Evaluation fails (useful for pinning down type errors) |

`kubeflight rules test rules.yaml` prints `PASS`/`FAIL` per test and exits `3` if any fail (`2` for an invalid file). `--require-tests` also fails rules with no tests. Put it in CI next to the check itself.

## Field validation and API removals

Two related checks need no rule file. `KF-FLD-001/002` validate core kinds (Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, Service, Ingress, ConfigMap, Secret, ServiceAccount, PVC, HPA, NetworkPolicy, PodDisruptionBudget, Role/ClusterRole and their bindings) against embedded field tables, so `replica:` is reported with "did you mean 'replicas'". Rarely used deep sub-objects (affinity, volumes, probe handlers, and so on) are accepted unchecked on purpose, so an incomplete table cannot cause a false unknown-field report. CRDs are skipped. `--no-field-check` disables it.

`--target-kubernetes 1.30` evaluates a hand-maintained table of deprecated and removed APIs (`KF-UPG-010` removed, `KF-UPG-011` deprecated) against that version. Verify against the [upstream deprecation guide](https://kubernetes.io/docs/reference/using-api/deprecation-guide/) for anything release-critical.
