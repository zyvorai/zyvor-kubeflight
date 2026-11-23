# Changelog

## Unreleased

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
