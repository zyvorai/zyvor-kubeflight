# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Exposure, access-control, storage and autoscaling checks."""
from __future__ import annotations
from typing import Any
from .models import Finding
from .parser import resource_key
from .quantities import memory_bytes, QuantityError

def _f(fid, sev, cat, title, res, evidence, rec):
    return Finding(fid, sev, cat, title, res, evidence, rec)

def _spec(o): return o.get("spec") or {}

def _wild(rule: dict[str, Any], keys=("verbs", "resources", "apiGroups")) -> list[str]:
    return [k for k in keys if "*" in (rule.get(k) or [])]

def exposure_findings(o: dict[str, Any], rk: str, baseline: dict[str, dict[str, Any]]) -> list[Finding]:
    out = []
    kind = o.get("kind")
    old = baseline.get(rk)
    if kind == "Service":
        t = _spec(o).get("type")
        if t in {"LoadBalancer", "NodePort"} and (old is None or _spec(old).get("type") != t):
            ranges = _spec(o).get("loadBalancerSourceRanges")
            open_lb = t == "LoadBalancer" and not ranges
            out.append(_f("KF-EXP-001", "high" if open_lb else "medium", "exposure",
                          f"Service exposed as {t}", rk,
                          f"type={t}" + ("; no loadBalancerSourceRanges" if open_lb else ""),
                          "Confirm external exposure is intended; restrict loadBalancerSourceRanges or use an internal load balancer."))
        if _spec(o).get("externalIPs"):
            out.append(_f("KF-EXP-003", "high", "exposure", "Service uses externalIPs", rk,
                          f"externalIPs={_spec(o)['externalIPs']}",
                          "externalIPs can hijack cluster traffic (CVE-2020-8554 class); prefer a LoadBalancer or Gateway."))
    elif kind == "Ingress":
        spec = _spec(o)
        if not spec.get("tls"):
            out.append(_f("KF-EXP-002", "medium", "exposure", "Ingress has no TLS configuration", rk,
                          "spec.tls is empty", "Terminate TLS on the Ingress (spec.tls with a certificate secret)."))
    return out

def rbac_findings(o: dict[str, Any], rk: str) -> list[Finding]:
    out = []
    kind = o.get("kind")
    if kind in {"ClusterRole", "Role"}:
        for i, rule in enumerate(o.get("rules") or []):
            w = _wild(rule if isinstance(rule, dict) else {})
            if "verbs" in w or "resources" in w:
                out.append(_f("KF-RBAC-020", "high" if kind == "ClusterRole" else "medium", "rbac",
                              f"{kind} grants wildcard access", rk,
                              f"rules[{i}] uses '*' for {', '.join(w)}",
                              "List the specific verbs and resources the workload needs."))
                break
    elif kind in {"ClusterRoleBinding", "RoleBinding"}:
        ref = o.get("roleRef") or {}
        if ref.get("name") == "cluster-admin":
            subj = ", ".join(f"{s.get('kind')}:{s.get('name')}" for s in (o.get("subjects") or []) if isinstance(s, dict))
            out.append(_f("KF-RBAC-021", "critical", "rbac", "Binding grants cluster-admin", rk,
                          f"subjects={subj or '<none>'}", "Bind a narrowly scoped role instead of cluster-admin."))
        for s in o.get("subjects") or []:
            if isinstance(s, dict) and s.get("name") in {"system:anonymous", "system:unauthenticated"}:
                out.append(_f("KF-RBAC-022", "critical", "rbac", "Binding grants access to anonymous users", rk,
                              f"subject={s.get('name')}", "Never bind roles to anonymous or unauthenticated subjects."))
    return out

def storage_findings(o: dict[str, Any], rk: str, baseline: dict[str, dict[str, Any]]) -> list[Finding]:
    old = baseline.get(rk)
    if o.get("kind") != "PersistentVolumeClaim" or old is None:
        return []
    try:
        new = memory_bytes((((_spec(o).get("resources") or {}).get("requests") or {}).get("storage")))
        prev = memory_bytes((((_spec(old).get("resources") or {}).get("requests") or {}).get("storage")))
    except (QuantityError, TypeError, ValueError):
        return []
    if new and prev and new < prev:
        return [_f("KF-STO-010", "critical", "storage", "PVC shrink is unsupported", rk,
                   f"requested storage decreases ({prev} -> {new} bytes)",
                   "Kubernetes cannot shrink a PVC; restore into a new, smaller volume instead.")]
    return []

def autoscaling_findings(o: dict[str, Any], rk: str) -> list[Finding]:
    if o.get("kind") != "HorizontalPodAutoscaler":
        return []
    s = _spec(o)
    lo, hi = s.get("minReplicas", 1), s.get("maxReplicas")
    out = []
    if isinstance(hi, int) and isinstance(lo, int) and lo > hi:
        out.append(_f("KF-REL-020", "critical", "reliability", "HPA minReplicas exceeds maxReplicas", rk,
                      f"minReplicas={lo} maxReplicas={hi}", "Set maxReplicas >= minReplicas."))
    elif lo == hi and isinstance(hi, int):
        out.append(_f("KF-REL-021", "low", "reliability", "HPA cannot scale (min equals max)", rk,
                      f"minReplicas=maxReplicas={hi}", "Widen the range or remove the HPA."))
    return out

def extra_findings(resources: list[dict[str, Any]], baseline: list[dict[str, Any]] | None) -> list[Finding]:
    base = {resource_key(o): o for o in (baseline or [])}
    out: list[Finding] = []
    for o in resources:
        if not isinstance(o, dict) or not o.get("kind"):
            continue
        rk = resource_key(o)
        out += exposure_findings(o, rk, base) + rbac_findings(o, rk) + storage_findings(o, rk, base) + autoscaling_findings(o, rk)
    return out
