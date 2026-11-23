---
hero:
  eyebrow: RULES
  title: Rules
---

Findings use five severities: `critical`, `high`, `medium`, `low`, `info`.

Critical findings include malformed/structurally invalid core objects, removed APIs, invalid resource quantities, privileged/HostProcess workloads, and workloads for which all replicas cannot be placed in the supplied snapshot.

High findings include Restricted Pod Security violations, blocked NetworkPolicy paths, missing required RBAC permissions, severe cost growth, and risky single-node replica concentration.

Rules are deterministic and include an evidence string plus a remediation recommendation. The engine does not silently convert unknown resource quantities to zero.

## Finding registry and `explain`

Every finding id lives in `kubeflight/registry.py` with its title, typical severity, category, rationale, fix and a reference link. Run `kubeflight explain KF-NET-020` for one entry or `kubeflight explain --list` for all of them. `--min-severity <level>` limits the findings printed in a report without changing the score or the `--fail-on` gate.

## Hardening, network and availability checks

| Id | Severity | What it flags |
|---|---|---|
| `KF-SEC-030` | low | ServiceAccount token auto-mounted (default or any SA) |
| `KF-SEC-031` | high | `hostPort` in a container port |
| `KF-SEC-032` | low | containerPort below 1024 without `NET_BIND_SERVICE` or a lowered `ip_unprivileged_port_start` |
| `KF-NET-010` / `011` | low / info | Namespace with workloads but no default-deny ingress / egress policy in the bundle |
| `KF-NET-012` | low | Namespace uses NetworkPolicies but none selects the workload |
| `KF-NET-020` / `021` | medium | Egress / ingress to `0.0.0.0/0`, `::/0` or an empty rule |
| `KF-NET-022` | low | `ipBlock` wider than /8 (IPv4) or /32 (IPv6) |
| `KF-NET-030` | medium | Allow-all ingress: no sources, empty peer or `namespaceSelector: {}` |
| `KF-REL-005` | medium | No requests and no limits (BestEffort) |
| `KF-REL-006` | high | Limit below request |
| `KF-REL-010` | medium | One replica (or HPA minimum of 1) behind a Service |
| `KF-REL-011` | high | PodDisruptionBudget that blocks drains |
| `KF-REL-012` | critical | RollingUpdate with `maxUnavailable` and `maxSurge` both zero |

Network posture checks only see NetworkPolicies in the submitted bundle; a default-deny that already exists in the cluster is not known unless it is included, so use `--ignore-file` for those namespaces.
