# Changelog

## Unreleased

### Added
- Exposure checks: `KF-EXP-001` (LoadBalancer/NodePort Services, high when a LoadBalancer has no `loadBalancerSourceRanges`; not re-flagged when unchanged against `--baseline`), `KF-EXP-002` (Ingress without TLS), `KF-EXP-003` (Service `externalIPs`).
- RBAC checks: `KF-RBAC-020` (wildcard verbs/resources), `KF-RBAC-021` (`cluster-admin` bindings), `KF-RBAC-022` (bindings to anonymous/unauthenticated).
- `KF-STO-010` PVC shrink against the baseline; `KF-REL-020`/`KF-REL-021` HPA bounds.
- Suppressions: `--ignore-file` (and `suppressions` on `POST /api/check`) take reviewed, reasoned entries with an optional expiry. Expired entries keep the finding and add `KF-SUP-900`; suppressing a critical finding needs an expiry (`KF-SUP-901`). Suppressed findings are listed under `suppressed` in the JSON report.
- `--fail-on` accepts `low` and `medium`.

### Fixed
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
