---
hero:
  eyebrow: RESEARCH
  title: Landscape research
---

How comparable tools work, what KubeFlight lacked, and why the 0.3 features were chosen. Sources were read in November 2026; details of fast-moving projects (Kubescape, kube-linter, Datree) should be re-checked before relying on them.

## What the tools do

| Tool | Approach | Customization | Source |
|---|---|---|---|
| kube-score | Static checks on manifests, 39 checks (33 default, 6 optional): resources, probes, security context, PDB, HPA, deprecated APIs. Few tunables (`--min-replicas-*`). | No custom rules; fixed catalogue | https://github.com/zegl/kube-score/blob/master/README_CHECKS.md |
| Polaris | Built-in checks plus custom checks written as JSON Schema with targets (`Controller`, `PodSpec`, `Container`), extra helpers (`resourceMinimum`) and Go templating | Declarative JSON Schema, severity set separately | https://polaris.docs.fairwinds.com/customization/custom-checks/ |
| kubeconform | Validates manifests against the official OpenAPI-derived JSON schemas; `-kubernetes-version`, `-strict` (rejects unknown fields and duplicate keys); CRDs need extra schema locations; fast, concurrent | Schema locations only | https://github.com/yannh/kubeconform |
| Kubescape | Scans local manifests or a live cluster against frameworks; custom controls and exceptions (not confirmed from the pages fetched) | Rego (reported, unverified here) | https://kubescape.io/docs/ |
| Kyverno | Kubernetes-native policy engine, policies in YAML, also mutate/generate; vendor sources say complex logic is harder than Rego | YAML patterns | https://nirmata.com/2026/01/28/whats-the-difference-between-kyverno-and-opa-gatekeeper/ |
| OPA Gatekeeper | ConstraintTemplate (Rego) plus Constraint (parameters, match); general-purpose language | Rego | https://computingforgeeks.com/opa-gatekeeper-vs-kyverno-policy/ |
| CEL / ValidatingAdmissionPolicy | A small non-Turing-complete expression language evaluated in the API server with variables, macros (`all`, `exists`, `filter`) and Kubernetes libraries (quantity, regex, semver). Cost limits bound evaluation. | Expressions in YAML | https://kubernetes.io/docs/reference/using-api/cel/ |
| Datree | CLI with central policy; custom rules as JSON Schema (also Rego/CEL). The company stopped maintaining it in July 2023. | JSON Schema | https://hub.datree.io/custom-rules-overview , https://github.com/datreeio/datree |
| Checkov | Python; YAML custom policies (attribute operators `equals`, `regex_match`, AND/OR, connection states) or Python classes | YAML or Python | https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html |
| kube-linter | Templates (parameterised check kinds) with custom checks defined in YAML from existing templates; new templates need Go | YAML over fixed templates | https://github.com/stackrox/kube-linter , https://www.redhat.com/en/blog/what-is-kubelinter |
| Trivy config scanning | Rego checks (`--config-check`), custom namespaces, schemas for Kubernetes/RBAC inputs | Rego | https://trivy.dev/docs/latest/scanner/misconfiguration/custom/ |
| Pluto | Finds deprecated and removed apiVersions in files, Helm charts and Helm releases; distinguishes DEPRECATED from REMOVED | Fixed catalogue | https://github.com/FairwindsOps/pluto |
| kubent | Uses per-version Rego rulesets; `--target-version` loads rules up to that version and suppresses earlier ones | Rulesets updatable without a new binary | https://github.com/doitintl/kube-no-trouble |

## Where KubeFlight was behind

1. **No user-defined rules.** Only the built-in catalogue; every team policy ("memory limit on every container", "approved registry") needed a code change.
2. **No schema awareness.** `replica: 3` or `value: 8080` passed silently (kubeconform's core value).
3. **Version-blind API removal.** One hard-coded list, no target version (Pluto, kubent, kubeconform all have one).
4. **No Helm/Kustomize change-impact view.** Not available in the surveyed tools either, as a first-class feature.

## Ranked ideas

| Rank | Idea | Rationale | Decision |
|---|---|---|---|
| 1 | Custom rules in a safe expression language | Every comparable tool has one; the gap that blocks adoption. Polaris/Datree JSON Schema and Checkov YAML are verbose for "all containers have X"; Rego (Gatekeeper, Trivy, Kubescape) needs a second language and runtime. A CEL-like expression with quantifiers keeps the rule readable and can be bounded. Python-only, zero new dependencies, no code execution. | Built (`KF-CUS-*`, `--rules`, `rules test`) |
| 2 | Offline field/type validation | kubeconform's strict mode is the most requested safety net; typos are the common cause of "silently ignored" settings. Embedded tables avoid network access and schema registries. Conservative (`any` for deep sub-objects) to avoid false positives. | Built (`KF-FLD-001/002`) |
| 3 | Per-version deprecated/removed API table | Pluto and kubent show demand; KubeFlight's old list ignored the target. Small, deterministic, and fits the existing `target_kubernetes` field. | Built (`--target-kubernetes`, `KF-UPG-010/011`) |
| 4 | Helm values / Kustomize overlay change-impact diff | Real gap, but depends on external renderers (`helm`, `kustomize`) that the test environment lacks, so it cannot be tested thoroughly here; `--baseline` already diffs rendered output. | Deferred |
| 5 | Full OpenAPI schema download (kubeconform style) | Complete, but needs network or large vendored schemas and tracks every Kubernetes release. | Rejected for now in favour of curated tables |
| 6 | Rego engine support | Ecosystem compatibility, but a heavy dependency and a large attack surface for untrusted rules. | Rejected |
| 7 | JSON Schema based rules (Polaris/Datree style) | Familiar, but poor at cross-field logic and quantifier-style checks; Datree's demise shows the risk of betting on one vendor format. | Rejected |

## Not built in this round

- Live CVE lookups, image scanning and registry digest resolution: need the network and a vulnerability database; KubeFlight only matches user-supplied SBOM and advisory files and says so.
- SPDX 3 / XML / tag-value SBOMs and CVSS v4 scoring: not parsed (clear error / default severity).
- Rendering charts for values checks (Helm unavailable in the test environment): values checks are key-name heuristics on the raw file.

## Design notes

- The expression language mirrors the useful core of CEL (paths, comparisons, `all`/`any` macros, quantity helpers) without importing a CEL runtime. Non-Turing-completeness plus an explicit step budget gives the termination guarantee CEL gets from its cost model.
- Regex is the one place a pure expression language can still hang (catastrophic backtracking in Python's `re`). The rule engine accepts only a restricted pattern subset and caps subject length instead of trying to interrupt `re`.
- Field-table incompleteness is handled by failing open: an unlisted deep sub-object is `any`, never "unknown".
