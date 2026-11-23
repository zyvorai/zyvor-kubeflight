---
hero:
  eyebrow: PROFILES
  title: Policy profiles
---

A profile chooses **which findings count** and **at what severity**. It does not change what KubeFlight detects: every check still runs, and the profile then drops, raises or lowers findings before the score, the decision and the `--fail-on` gate are computed. The JSON report records what happened under `profile` (`dropped`, `adjusted`, `protected_critical`), so nothing is hidden silently.

```bash
kubeflight check deploy/ --profile restricted
kubeflight check deploy/ --profile-file team-profile.yaml            # your own
kubeflight check deploy/ --profile baseline --profile-file mine.yaml # yours, layered on a preset
kubeflight profiles list
kubeflight profiles show strict
```

`--profile` also sets the default gate: the profile's `fail_on` applies unless you pass `--fail-on` explicitly. The same options exist on `kubeflight values`, and the API accepts `profile` (a preset name) or `profile_spec` (an inline profile document) on `POST /api/check` and `POST /api/values`; `GET /api/profiles` lists the presets.

## Rules of the game

- **Critical findings cannot be hidden or lowered by a profile.** They can be raised. To accept a critical finding use `--ignore-file` with an `expires` date.
- `enable` beats `disable` within a layer, and a later layer (your file, or a preset that `extends` another) beats an earlier one. An explicit `enable` also beats `min_severity`.
- An exact id beats a pattern (`KF-NET-*`) in the same layer.
- Severity overrides are applied first, then `min_severity` is checked against the effective severity.
- Every id or pattern must match something in the registry (`kubeflight explain --list`); a typo is an error, not a silent no-op. Custom rule ids (`KF-CUS-*`) are accepted.

## Profile file format

```yaml
name: team                 # optional label
description: What this is for.
extends: restricted        # optional built-in preset to start from
min_severity: low          # findings below this (after overrides) are not counted
fail_on: high              # default gate: never | low | medium | high | critical
severity:                  # id or pattern -> severity
  KF-SEC-030: medium
  "KF-NET-*": low
enable: [KF-REL-004]       # always count, even below min_severity
disable: [KF-NET-011]      # do not count (never applies to critical findings)
```

Files are limited to 128 KiB and are parsed with a safe YAML loader.

## Built-in presets

The preset files live in `kubeflight/profiles/*.yaml`; a test checks that every id they reference exists in the registry and that each preset is documented below.


## `baseline`

Pod Security Baseline posture. Hardening that only the Restricted standard requires is downgraded, informational noise is dropped, everything else counts.

```yaml
min_severity: low
fail_on: critical
```

| Id | Severity | Why |
|---|---|---|
| `KF-SEC-010` | low | Non-root execution not proven |
| `KF-SEC-011` | low | Seccomp profile missing or invalid |
| `KF-SEC-021` | low | Privilege escalation not disabled |
| `KF-SEC-022` | medium | Capabilities violate Restricted policy |
| `KF-SEC-023` | info | Writable root filesystem |
| `KF-PSS-009` | low | Container explicitly runs as UID 0 |

Everything not listed keeps its default severity; findings under `low` are not counted.


## `restricted`

Pod Security Restricted posture plus network and exposure hygiene. Hardening gaps are raised and the gate fails on high.

```yaml
min_severity: low
fail_on: high
```

| Id | Severity | Why |
|---|---|---|
| `KF-SEC-023` | medium | Writable root filesystem |
| `KF-SEC-030` | medium | ServiceAccount token auto-mounted |
| `KF-NET-010` | medium | Namespace has no default-deny ingress policy |
| `KF-NET-011` | low | Namespace has no default-deny egress policy |
| `KF-NET-012` | medium | Workload selected by no NetworkPolicy |
| `KF-SUP-001` | high | Unpinned image |
| `KF-EXP-002` | high | Ingress has no TLS configuration |
| `KF-IMG-001` | low | Image not pinned by digest |
| `KF-HLM-004` | high | Values leave resource requests empty |

Restricted does not extend `baseline`: the Pod Security hardening findings keep their full severity.


## `strict`

Everything counts, including informational findings, with supply-chain, probe and network gaps raised. The gate fails on medium.

```yaml
min_severity: info
fail_on: medium
```

Extends `restricted`; the entries below are added on top of it.

| Id | Severity | Why |
|---|---|---|
| `KF-IMG-001` | medium | Image not pinned by digest |
| `KF-IMG-002` | high | Mutable image tag |
| `KF-REL-002` | medium | Memory limit missing |
| `KF-REL-004` | medium | Liveness probe missing |
| `KF-ROL-001` | medium | No matching PodDisruptionBudget |
| `KF-SEC-032` | medium | Privileged port without NET_BIND_SERVICE |
| `KF-NET-011` | medium | Namespace has no default-deny egress policy |
| `KF-NET-022` | medium | ipBlock is overly wide |
| `KF-FLD-001` | high | Unknown field in manifest |
| `KF-RBAC-001` | medium | ServiceAccount not present in bundle or target snapshot |
| `KF-HLM-007` | high | Values contain a hard-coded secret |
| `KF-VUL-003` | medium | Advisory data has no version or expiry |
| `KF-VUL-005` | low | No SBOM for image |


## `permissive`

Blockers only. Findings below high severity do not count, so the score and the gate reflect only high and critical problems. Critical findings can never be hidden.

```yaml
min_severity: high
fail_on: critical
```

No per-id overrides. Everything below `high` is simply not counted.
