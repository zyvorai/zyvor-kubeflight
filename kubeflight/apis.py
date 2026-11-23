# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Deprecated / removed Kubernetes API table, evaluated against a target version.

Each entry says in which minor release an (apiVersion, kind) was deprecated and
removed, plus the replacement. A manifest is only flagged relative to the
``--target-kubernetes`` version: an API removed in 1.25 is fine against 1.24.
The table is hand-maintained from the upstream deprecation guide
(https://kubernetes.io/docs/reference/using-api/deprecation-guide/).
"""
from __future__ import annotations
import re
from typing import Any
from .models import Finding
from .parser import resource_key

Version = tuple[int, int]
_VER = re.compile(r"^v?(\d{1,3})\.(\d{1,4})(?:\.\d{1,4})?(?:[-+][0-9A-Za-z.+-]*)?$")

def parse_version(text: str) -> Version:
    m = _VER.match(str(text).strip())
    if not m:
        raise ValueError(f"invalid Kubernetes version {text!r}; expected MAJOR.MINOR such as 1.31")
    return int(m.group(1)), int(m.group(2))

def _v(s: str | None) -> Version | None:
    return None if s is None else parse_version(s)

# (apiVersion, kind or "*") -> (deprecated_in, removed_in, replacement)
# removed_in None means "deprecated but still served".
_RAW: dict[tuple[str, str], tuple[str, str | None, str]] = {}

def _add(api: str, kinds: str, dep: str, rem: str | None, repl: str) -> None:
    for k in kinds.split():
        _RAW[(api, k)] = (dep, rem, repl)

_add("extensions/v1beta1", "Deployment DaemonSet ReplicaSet", "1.9", "1.16", "apps/v1")
_add("extensions/v1beta1", "NetworkPolicy", "1.9", "1.16", "networking.k8s.io/v1")
_add("extensions/v1beta1", "PodSecurityPolicy", "1.10", "1.16", "Pod Security Admission (policy/v1beta1 PSP was itself removed in 1.25)")
_add("extensions/v1beta1", "Ingress", "1.14", "1.22", "networking.k8s.io/v1")
_add("extensions/v1beta1", "*", "1.14", "1.22", "the stable API for this kind")
_add("apps/v1beta1", "Deployment StatefulSet", "1.9", "1.16", "apps/v1")
_add("apps/v1beta2", "Deployment StatefulSet DaemonSet ReplicaSet", "1.9", "1.16", "apps/v1")
_add("apps/v1beta1", "*", "1.9", "1.16", "apps/v1")
_add("apps/v1beta2", "*", "1.9", "1.16", "apps/v1")
_add("batch/v1beta1", "CronJob", "1.21", "1.25", "batch/v1")
_add("batch/v2alpha1", "CronJob", "1.8", "1.21", "batch/v1")
_add("policy/v1beta1", "PodDisruptionBudget", "1.21", "1.25", "policy/v1")
_add("policy/v1beta1", "PodSecurityPolicy", "1.21", "1.25", "Pod Security Admission or a policy engine")
_add("autoscaling/v2beta1", "HorizontalPodAutoscaler", "1.22", "1.25", "autoscaling/v2")
_add("autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.23", "1.26", "autoscaling/v2")
_add("networking.k8s.io/v1beta1", "Ingress IngressClass", "1.19", "1.22", "networking.k8s.io/v1")
_add("discovery.k8s.io/v1beta1", "EndpointSlice", "1.21", "1.25", "discovery.k8s.io/v1")
_add("events.k8s.io/v1beta1", "Event", "1.19", "1.25", "events.k8s.io/v1")
_add("node.k8s.io/v1beta1", "RuntimeClass", "1.22", "1.25", "node.k8s.io/v1")
_add("storage.k8s.io/v1beta1", "CSIStorageCapacity", "1.24", "1.27", "storage.k8s.io/v1")
_add("storage.k8s.io/v1beta1", "CSIDriver CSINode StorageClass VolumeAttachment", "1.19", "1.22", "storage.k8s.io/v1")
_add("flowcontrol.apiserver.k8s.io/v1beta1", "FlowSchema PriorityLevelConfiguration", "1.23", "1.26", "flowcontrol.apiserver.k8s.io/v1")
_add("flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema PriorityLevelConfiguration", "1.26", "1.29", "flowcontrol.apiserver.k8s.io/v1")
_add("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema PriorityLevelConfiguration", "1.29", "1.32", "flowcontrol.apiserver.k8s.io/v1")
_add("admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration MutatingWebhookConfiguration", "1.16", "1.22", "admissionregistration.k8s.io/v1")
_add("apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", "1.16", "1.22", "apiextensions.k8s.io/v1")
_add("apiregistration.k8s.io/v1beta1", "APIService", "1.10", "1.22", "apiregistration.k8s.io/v1")
_add("certificates.k8s.io/v1beta1", "CertificateSigningRequest", "1.19", "1.22", "certificates.k8s.io/v1")
_add("coordination.k8s.io/v1beta1", "Lease", "1.19", "1.22", "coordination.k8s.io/v1")
_add("rbac.authorization.k8s.io/v1beta1", "Role ClusterRole RoleBinding ClusterRoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1")
_add("scheduling.k8s.io/v1beta1", "PriorityClass", "1.14", "1.22", "scheduling.k8s.io/v1")
_add("authentication.k8s.io/v1beta1", "TokenReview", "1.19", "1.22", "authentication.k8s.io/v1")
_add("authorization.k8s.io/v1beta1", "SubjectAccessReview LocalSubjectAccessReview SelfSubjectAccessReview SelfSubjectRulesReview", "1.19", "1.22", "authorization.k8s.io/v1")
_add("v1", "Endpoints", "1.33", None, "discovery.k8s.io/v1 EndpointSlice")

TABLE: dict[tuple[str, str], tuple[Version, Version | None, str]] = {
    k: (parse_version(d), _v(r), repl) for k, (d, r, repl) in _RAW.items()
}

def lookup(api: str, kind: str):
    return TABLE.get((api, kind)) or TABLE.get((api, "*"))

def api_findings(resources: list[dict[str, Any]], target: str) -> list[Finding]:
    """KF-UPG-010 (removed at target, critical) and KF-UPG-011 (deprecated, medium; low for v1 Endpoints)."""
    tv = parse_version(target)
    out: list[Finding] = []
    for o in resources:
        if not isinstance(o, dict) or not isinstance(o.get("apiVersion"), str) or not isinstance(o.get("kind"), str):
            continue
        hit = lookup(o["apiVersion"], o["kind"])
        if hit is None:
            continue
        dep, rem, repl = hit
        rk = resource_key(o)
        what = f"{o['apiVersion']} {o['kind']}"
        if rem is not None and tv >= rem:
            out.append(Finding("KF-UPG-010", "critical", "upgrade", f"API removed in Kubernetes {rem[0]}.{rem[1]}", rk,
                               f"{what} was deprecated in {dep[0]}.{dep[1]} and removed in {rem[0]}.{rem[1]}; target is {tv[0]}.{tv[1]}",
                               f"Migrate to {repl}."))
        elif tv >= dep:
            tail = f"; removal in {rem[0]}.{rem[1]}" if rem else "; no removal planned yet"
            out.append(Finding("KF-UPG-011", "low" if rem is None else "medium", "upgrade", f"API deprecated since Kubernetes {dep[0]}.{dep[1]}", rk,
                               f"{what} is deprecated as of {dep[0]}.{dep[1]}{tail}", f"Plan the move to {repl}."))
    return out
