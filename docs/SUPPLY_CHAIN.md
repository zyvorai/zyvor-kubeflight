---
hero:
  eyebrow: SUPPLY CHAIN
  title: Image hygiene, SBOMs and advisories
---

KubeFlight is local-first and offline. These checks never contact a registry or a vulnerability database and never inspect image contents.

!!! warning "This is not a vulnerability scanner"
    KubeFlight only compares an SBOM and an advisory file **that you supply**. A component with no matching advisory is not "clean": the advisory file may be incomplete or stale, version comparison is a tolerant approximation of each ecosystem's rules, and an SBOM is bound to a workload by image repository (plus tag or digest when both are known). Use a real scanner (Trivy, Grype, Scout) to produce SBOMs and advisories, and use KubeFlight to gate the change in review.

## Image reference hygiene (no registry needed)

| Id | Default severity | Flags |
|---|---|---|
| `KF-IMG-001` | info (medium with `require_digest`) | image not pinned by `@sha256:` digest |
| `KF-IMG-002` | medium | moving tags such as `stable`, `main`, `dev`, `nightly` (without a digest); `latest` and untagged stay `KF-SUP-001` |
| `KF-IMG-003` | high | registry not in your allow-list |
| `KF-IMG-004` | medium | malformed reference (spaces, upper case, unexpanded `${VAR}`, bad digest) |

```bash
kubeflight check deploy/ --image-policy image-policy.yaml --allow-registry ghcr.io/acme/*
```

```yaml
# image-policy.yaml
allowed_registries:        # fnmatch patterns; "host/path/*" limits to a path prefix
  - ghcr.io/example/*
  - registry.example.com
require_digest: false
```

Docker Hub images are normalised to `docker.io/library/...`, so allow `docker.io` explicitly if you use it.

## SBOM and advisory matching

```bash
kubeflight check deploy/ \
  --sbom payments.cdx.json --sbom nginx.spdx.json=docker.io/library/nginx:1.27 \
  --advisories advisories.yaml
```

Both flags are repeatable and must be used together. The API equivalents are `sboms` (a list of `{document, image?}`), `advisories` (a list of documents), `image_policy` and `allow_registries` on `POST /api/check`.

**SBOMs**: CycloneDX JSON and SPDX 2.x JSON, up to 8 MiB and 50,000 components, nesting limited. The SBOM's subject (CycloneDX `metadata.component`, or the SPDX described package/document name) is matched to a workload image by repository; when both sides have a tag they must agree, when both have a digest they must be equal. Bind explicitly with `FILE=IMAGE` or a `kubeflight:image` property. Unmatched SBOMs raise `KF-VUL-004`; images no SBOM covers raise `KF-VUL-005` (info).

**Advisories**: either the simple format or an OSV-style subset, in JSON or YAML.

```yaml
version: "2026-11-01"     # label of the data set
expires: 2027-01-31       # stale after this date -> KF-VUL-002
advisories:
  - id: CVE-2026-0001
    package: openssl      # or {name, ecosystem, purl}
    ecosystem: debian
    affected: ["<3.0.13", ">=3.1,<3.1.5"]   # OR of comma-joined AND constraints
    fixed: 3.0.13
    severity: high        # critical|high|medium|low
    summary: free text
```

OSV: a vulnerability object, a list, or `{version, expires, vulns: [...]}`; `affected[].ranges` of type `SEMVER`/`ECOSYSTEM` with `introduced`/`fixed`/`last_affected` events and `affected[].versions` are used (GIT ranges cannot apply to package versions and are ignored).

**Severity is transparent.** In order: the advisory's own `severity`, OSV `database_specific.severity`, a CVSS v3.0/3.1 vector (the base score is computed locally), a numeric score, `ecosystem_specific.severity`, and otherwise a `medium` default. The finding's evidence names which source was used, the matched component, the affected range, the fix version, and the data set `version`/`expires`. CVSS v4 vectors are not computed and fall through to the default.

**Stale data is called out.** An `expires` date in the past raises `KF-VUL-002`; a file with neither `version` nor `expires` raises `KF-VUL-003`. Findings are capped at 500 (`KF-VUL-006`).

Findings are `KF-VUL-001` (one per workload and advisory id), with the advisory's severity. Treat them as input to a review: suppress with a reasoned, expiring `--ignore-file` entry when a component is present but not reachable.

Every report (JSON `limitations`, SARIF help, markdown) carries the not-a-scanner caveats when these inputs are used. Example files live in `examples/supply/`.

## Helm values hygiene

`kubeflight values values.yaml` (also a chart directory, which reads `values*.yaml`) checks a raw values file without rendering the chart. Findings name the key path and line (`Values/values.yaml:ingress`), and **secret values are never printed**.

| Id | Severity | Flags |
|---|---|---|
| `KF-HLM-001` | high | `privileged`, `allowPrivilegeEscalation`, `hostPID`, `hostIPC` true; `runAsNonRoot: false`; `runAsUser: 0` |
| `KF-HLM-002` | high | `hostNetwork: true` |
| `KF-HLM-003` | medium | `tag: latest`, `image: x:latest`, moving tags |
| `KF-HLM-004` | medium | `resources:` empty or without complete requests |
| `KF-HLM-005` | medium | `ingress.enabled: true` with no `tls` |
| `KF-HLM-006` | high | credential-named key (`password`, `token`, `apiKey`, `secret`...) set to a well-known default (`admin`, `changeme`, ...) |
| `KF-HLM-007` | medium | credential-named key with any other literal value |

`existingSecret`-style keys, empty values and templated values (`{{ }}`, `${VAR}`) are not flagged. Limits: 512 KiB per file, 50,000 nodes (alias expansion is bounded), depth 40. The checks are heuristics on key names: a chart that nests these keys differently, or renders them from templates, can be missed, and a value that is only illustrative can be flagged. Use `--profile`, `--ignore-file` and `--min-severity` as with `check`.
