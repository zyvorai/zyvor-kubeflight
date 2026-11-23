# Changelog

## Unreleased

### Added (supply chain, profiles, CI, values)
- Image hygiene without a registry: `KF-IMG-001` (no digest), `KF-IMG-002` (moving tag), `KF-IMG-003` (registry outside the allow-list), `KF-IMG-004` (malformed reference). `--image-policy FILE` / `--allow-registry` (and `image_policy`, `allow_registries` in the API).
- Offline SBOM and advisory matching: `--sbom FILE[=IMAGE]` (CycloneDX JSON, SPDX 2.x JSON) with `--advisories FILE` (simple format or OSV subset with `version`/`expires`). `KF-VUL-001` (known-vulnerable component, severity from the advisory with a stated source, CVSS v3 computed locally), `KF-VUL-002` (stale data), `KF-VUL-003` (no version/expiry), `KF-VUL-004`..`006` (coverage and truncation). Explicitly not a scanner; limitations are added to every report. See `docs/SUPPLY_CHAIN.md`, `examples/supply/`.
- Policy profiles: `--profile baseline|restricted|strict|permissive` and `--profile-file FILE` (data files in `kubeflight/profiles/`), `kubeflight profiles list|show`, `profile` in the JSON report and API. Critical findings can be raised but never hidden. See `docs/PROFILES.md`.
- PR/CI: `--format pr-comment`, `--baseline-report`, `--fail-on-new [SEV]`, `kubeflight diff-report old.json new.json`, SARIF `baselineState`, `POST /api/diff`. `action.yml` exposes profile, baseline report, fail-on-new, supply-chain inputs and a `pr-comment` output. See `docs/CI_INTEGRATION.md`.
- `kubeflight values FILE|DIR...` and `POST /api/values`: Helm values hygiene `KF-HLM-001`..`007` on a raw values file (never prints secret values; line-accurate SARIF locations).
- Dashboard: findings link to the registry explanation (`GET /api/rules/{id}`, `GET /api/rules`) and a read-only panel lists suppressed findings and the active profile. No build step.

### Fixed (this round)
- `action.yml` appended the Step Summary only if the gate passed; a failing gate skipped it. The summary is now published first.
- `--fail-on` default now comes from the profile when one is selected (still `critical` otherwise).


### Added (custom rules, field validation, API removal table)
- Custom rules: `kubeflight check|plan --rules FILE` (repeatable; also `rules` on `POST /api/check`) loads YAML rules (`KF-CUS-NNN`) written in a small sandboxed expression language (path selectors, comparisons, `all`/`any` quantifiers, a handful of functions). No `eval`/`exec`; the interpreter enforces size, nesting, step and regex-safety limits, and evaluation failures surface as `KF-CUS-900` findings instead of crashing the run. See `docs/CUSTOM_RULES.md` and `examples/rules/`.
- `kubeflight rules test FILE...` runs the tests embedded in rule files (`--require-tests` fails rules without any).
- Offline field/type validation for core kinds against embedded field tables: `KF-FLD-001` unknown field (with "did you mean"), `KF-FLD-002` wrong type (for example a numeric ConfigMap value or env `value: 8080`). CRDs and unknown groups are skipped; `--no-field-check` turns it off.
- `--target-kubernetes` (also `target_kubernetes` in the API): a per-version deprecated/removed API table. `KF-UPG-010` (removed at the target, critical) and `KF-UPG-011` (deprecated, medium), with the replacement API. It supersedes the version-blind `KF-UPG-001` for the same resource.
- `docs/RESEARCH.md`: survey of comparable tools and why these features were chosen.

### Added
- Pod security extras: `KF-SEC-030` (auto-mounted ServiceAccount token, honours `automountServiceAccountToken: false` on the Pod or ServiceAccount), `KF-SEC-031` (`hostPort`), `KF-SEC-032` (port below 1024 without `NET_BIND_SERVICE`). Non-root, read-only root filesystem and seccomp checks already existed as `KF-SEC-010`/`KF-SEC-023`/`KF-SEC-011`.
- NetworkPolicy posture: `KF-NET-010`/`KF-NET-011` (namespace without default-deny ingress/egress), `KF-NET-012` (workload selected by no policy), `KF-NET-020`/`KF-NET-021` (egress/ingress to `0.0.0.0/0`, `::/0` or an empty rule), `KF-NET-022` (very wide `ipBlock`), `KF-NET-030` (allow-all ingress: no sources, empty peer or `namespaceSelector: {}`).
- Reliability: `KF-REL-005` (no requests or limits, BestEffort), `KF-REL-006` (limit below request), `KF-REL-010` (single replica behind a Service; HPA `minReplicas` is honoured), `KF-REL-011` (PodDisruptionBudget that blocks drains: `minAvailable` >= replicas, `100%` or `maxUnavailable: 0`), `KF-REL-012` (RollingUpdate with `maxUnavailable` and `maxSurge` both 0).
- `kubeflight explain KF-XXX-NNN` (also `--list`, `--json`) prints a check's rationale, fix and reference from the new findings registry (`kubeflight/registry.py`). A test asserts every id the engine can emit is registered.
- `--min-severity` on `check`/`plan` limits the findings shown in the report; score, decision and the `--fail-on` gate still use every finding.
- SARIF: rule `help` (text and markdown), `helpUri`, `fullDescription`, `defaultConfiguration`, `security-severity`, tags, `ruleIndex`, tool version, and `physicalLocation` (file and start line) for resources read from manifest files; logical resource locations are always included.
- Exposure checks: `KF-EXP-001` (LoadBalancer/NodePort Services, high when a LoadBalancer has no `loadBalancerSourceRanges`; not re-flagged when unchanged against `--baseline`), `KF-EXP-002` (Ingress without TLS), `KF-EXP-003` (Service `externalIPs`).
- RBAC checks: `KF-RBAC-020` (wildcard verbs/resources), `KF-RBAC-021` (`cluster-admin` bindings), `KF-RBAC-022` (bindings to anonymous/unauthenticated).
- `KF-STO-010` PVC shrink against the baseline; `KF-REL-020`/`KF-REL-021` HPA bounds.
- Suppressions: `--ignore-file` (and `suppressions` on `POST /api/check`) take reviewed, reasoned entries with an optional expiry. Expired entries keep the finding and add `KF-SUP-900`; suppressing a critical finding needs an expiry (`KF-SUP-901`). Suppressed findings are listed under `suppressed` in the JSON report.
- `--fail-on` accepts `low` and `medium`.

### Fixed
- `replicas: 0` was treated as 1 replica.
- NetworkPolicy path analysis: a policy with no `policyTypes` now defaults to Ingress as Kubernetes does (a bare `podSelector: {}` is a default-deny), and an empty `from`, `to` or `ports` list matches everything instead of nothing (false `KF-NET-001`).
- Readiness/liveness probe findings (`KF-REL-003`/`KF-REL-004`) are no longer raised for Job and CronJob containers.
- A non-numeric `runAsUser` no longer crashes the analysis, and a null `windowsOptions` is tolerated.
- SARIF no longer raises on an unknown severity.
- `pytest -q` now works from a clean checkout (`pythonpath` configured); CI previously relied on `PYTHONPATH`.
- Markdown reports escape table separators, backticks and HTML in resource names and titles taken from manifests.

### Changed
- Dependencies: PyYAML 6.0.4, uvicorn 0.54.0 (fastapi, pytest and httpx were already current).

## 0.2.0 — 2026-09-06

### Correctness
- Kubernetes quantity parsing now supports DecimalSI, BinarySI and scientific notation and rejects invalid quantities.
- Scheduler subtracts existing non-terminal Pod reservations and places every proposed replica.
- Correct app/init/native-sidecar request accounting plus RuntimeClass overhead, ephemeral storage and extended resources.
- Node selectors, taints/tolerations, required node affinity, required pod affinity/anti-affinity and hard topology spread simulation.
- Deletion-aware blast radius combines baseline and proposed dependency graphs.
- Dependency discovery no longer scans image strings, preventing `redis:7.4.0`-style false edges.
- NetworkPolicy analysis covers both ingress and egress with selectors and ports.
- Rich RBAC permission contracts support API groups, verbs and resourceNames.

### Security
- Expanded Restricted Pod Security checks including Windows HostProcess, explicit UID 0, SELinux/AppArmor, sysctls, probe/lifecycle hosts and ephemeral containers.
- Default Kubernetes deployment no longer mounts a service-account token or grants cluster-wide RBAC.
- Live cluster mode is explicit, read-only and requires bearer authentication.
- API body, concurrency and per-client rate guards added.

### Developer experience
- `kubeflight plan` auto-detects common deployment roots and Helm/Kustomize renderers.
- Markdown and SARIF reports added.
- GitHub Action emits JSON, SARIF and a step summary.
- CI includes Helm/Kustomize validation, container build and kind E2E.
- Release workflow includes standalone binaries, multi-arch images, SBOM and provenance wiring.

## 0.1.0
- Initial public prototype.
