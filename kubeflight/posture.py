# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Workload hardening, NetworkPolicy posture and availability checks that look across resources."""
from __future__ import annotations
import ipaddress
from typing import Any
from .models import Finding
from .parser import resource_key
from .quantities import cpu_millicores, memory_bytes, QuantityError

SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
REPLICA_KINDS = {"Deployment", "StatefulSet"}


def _f(fid, sev, cat, title, res, evidence, rec):
    return Finding(fid, sev, cat, title, res, evidence, rec)

def _ns(o): return (o.get("metadata") or {}).get("namespace", "default")
def _spec(o): return o.get("spec") or {}
def _dict(v): return v if isinstance(v, dict) else {}
def _list(v): return v if isinstance(v, list) else []

def _is_zero(v) -> bool:
    return v is not None and not isinstance(v, bool) and str(v).strip() in {"0", "0%"}

def _empty_selector(sel) -> bool:
    sel = sel if isinstance(sel, dict) else {}
    return not sel.get("matchLabels") and not sel.get("matchExpressions")

def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None

# ---------------------------------------------------------------- workloads

def _hpa_min(resources) -> dict[tuple[str, str, str], int]:
    out = {}
    for o in resources:
        if o.get("kind") == "HorizontalPodAutoscaler":
            ref = _dict(_spec(o).get("scaleTargetRef"))
            lo = _spec(o).get("minReplicas", 1)
            if ref.get("kind") and ref.get("name") and _int(lo) is not None:
                out[(ref["kind"], _ns(o), ref["name"])] = lo
    return out

def _effective_replicas(o, hpa) -> int:
    from .engine import _replicas
    key = (o.get("kind"), _ns(o), (o.get("metadata") or {}).get("name"))
    return hpa[key] if key in hpa else _replicas(o)

def _container_findings(o, pod, rk, sa_no_mount) -> list[Finding]:
    out = []
    sa = pod.get("serviceAccountName") or "default"
    if pod.get("automountServiceAccountToken") is not False and (_ns(o), sa) not in sa_no_mount:
        who = "the default ServiceAccount" if sa == "default" else f"ServiceAccount {sa}"
        out.append(_f("KF-SEC-030", "low", "security", "ServiceAccount token is auto-mounted", rk,
                      f"uses {who} and automountServiceAccountToken is not false",
                      "Set automountServiceAccountToken: false on the Pod spec (or the ServiceAccount) unless the workload calls the Kubernetes API."))
    psc = _dict(pod.get("securityContext"))
    sysctls = {s.get("name"): s.get("value") for s in _list(psc.get("sysctls")) if isinstance(s, dict)}
    try:
        unpriv_start = int(sysctls.get("net.ipv4.ip_unprivileged_port_start"))
    except (TypeError, ValueError):
        unpriv_start = None
    for c in _list(pod.get("containers")):
        if not isinstance(c, dict): continue
        name = c.get("name", "container"); sc = _dict(c.get("securityContext"))
        res = _dict(c.get("resources")); req = _dict(res.get("requests")); lim = _dict(res.get("limits"))
        ports = [p for p in _list(c.get("ports")) if isinstance(p, dict)]
        hp = [p for p in ports if p.get("hostPort")]
        if hp:
            out.append(_f("KF-SEC-031", "high", "security", f"hostPort used: {name}", rk,
                          "hostPort=" + ", ".join(str(p["hostPort"]) for p in hp),
                          "Remove hostPort and expose the container through a Service."))
        adds = set(_dict(sc.get("capabilities")).get("add") or [])
        uid = sc.get("runAsUser", psc.get("runAsUser"))
        low_ports = [p["containerPort"] for p in ports
                     if _int(p.get("containerPort")) is not None and 0 < p["containerPort"] < 1024
                     and (unpriv_start is None or p["containerPort"] < unpriv_start)]
        if low_ports and "NET_BIND_SERVICE" not in adds and uid != 0:
            out.append(_f("KF-SEC-032", "low", "security", f"Privileged port without NET_BIND_SERVICE: {name}", rk,
                          "containerPort " + ", ".join(map(str, low_ports)) + " is below 1024",
                          "Listen on a port >= 1024 and map it in the Service, or add NET_BIND_SERVICE after dropping ALL."))
        if not req and not lim:
            out.append(_f("KF-REL-005", "medium", "reliability", f"No resource requests or limits: {name}", rk,
                          "container has no resources.requests or resources.limits (BestEffort QoS)",
                          "Set CPU/memory requests and a memory limit."))
        for rname, conv in (("cpu", cpu_millicores), ("memory", memory_bytes)):
            if rname in req and rname in lim:
                try:
                    if conv(lim[rname]) < conv(req[rname]):
                        out.append(_f("KF-REL-006", "high", "reliability", f"{rname} limit below request: {name}", rk,
                                      f"requests.{rname}={req[rname]} limits.{rname}={lim[rname]}", "Set limits >= requests."))
                except (QuantityError, TypeError, ValueError):
                    pass  # reported as KF-RES-001
    return out

def _strategy_findings(o, rk) -> list[Finding]:
    kind = o.get("kind"); spec = _spec(o)
    if kind == "Deployment":
        st = _dict(spec.get("strategy"))
        if st.get("type", "RollingUpdate") != "RollingUpdate": return []
        ru = _dict(st.get("rollingUpdate"))
        mu, ms = ru.get("maxUnavailable"), ru.get("maxSurge")
        stuck = _is_zero(mu) and _is_zero(ms)
    elif kind == "DaemonSet":
        st = _dict(spec.get("updateStrategy"))
        if st.get("type", "RollingUpdate") != "RollingUpdate": return []
        ru = _dict(st.get("rollingUpdate"))
        mu, ms = ru.get("maxUnavailable"), ru.get("maxSurge")
        stuck = _is_zero(mu) and (ms is None or _is_zero(ms))
    else:
        return []
    if stuck:
        return [_f("KF-REL-012", "critical", "reliability", "RollingUpdate cannot make progress", rk,
                   f"maxUnavailable={mu} and maxSurge={ms if ms is not None else 0}; the API server rejects this",
                   "Allow maxSurge or maxUnavailable to be at least 1 (or a non-zero percentage).")]
    return []

def _availability_findings(resources, hpa) -> list[Finding]:
    from .engine import _pod_spec, _selector_labels, _selector_matches
    out = []
    services = [o for o in resources if o.get("kind") == "Service"]
    pdbs = [o for o in resources if o.get("kind") == "PodDisruptionBudget"]
    for o in resources:
        if o.get("kind") not in REPLICA_KINDS: continue
        pod, _ = _pod_spec(o)
        if pod is None: continue
        rk = resource_key(o); labels = _selector_labels(o); eff = _effective_replicas(o, hpa)
        if eff == 1:
            for s in services:
                sel = _dict(_spec(s).get("selector"))
                if sel and _ns(s) == _ns(o) and all(labels.get(k) == str(v) for k, v in sel.items()):
                    out.append(_f("KF-REL-010", "medium", "reliability", "Single replica behind a Service", rk,
                                  f"replicas=1 and Service {resource_key(s)} routes to it; every rollout or drain causes downtime",
                                  "Run at least 2 replicas with topology spread or anti-affinity, or document the accepted downtime."))
                    break
        if eff >= 1:
            for pdb in pdbs:
                ps = _spec(pdb)
                if _ns(pdb) != _ns(o) or not _selector_matches(ps.get("selector") or {}, labels): continue
                ma, mu = ps.get("minAvailable"), ps.get("maxUnavailable")
                why = None
                if _int(ma) is not None and ma >= eff: why = f"minAvailable={ma} >= replicas={eff}"
                elif isinstance(ma, str) and ma.strip() == "100%": why = f"minAvailable=100% with replicas={eff}"
                elif _is_zero(mu): why = f"maxUnavailable={mu}"
                if why:
                    out.append(_f("KF-REL-011", "high", "reliability", "PodDisruptionBudget blocks voluntary disruptions", resource_key(pdb),
                                  f"{why} for {rk}; node drains and upgrades cannot evict its Pods",
                                  "Use minAvailable of replicas-1 or maxUnavailable: 1."))
    return out

# ------------------------------------------------------------- networkpolicy

def _np_types(spec) -> list[str]:
    t = spec.get("policyTypes")
    if t: return list(t)
    # Kubernetes always defaults to Ingress, and adds Egress only when egress rules exist.
    return ["Ingress"] + (["Egress"] if "egress" in spec else [])

def _cidr_issue(cidr) -> str | None:
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return None
    if net.prefixlen == 0: return "any"
    if net.prefixlen < (8 if net.version == 4 else 32): return "wide"
    return None

def _ports_text(rule) -> str:
    ports = rule.get("ports")
    if not ports: return " and no ports: allows all traffic"
    return f" (ports {[p.get('port') for p in ports if isinstance(p, dict)]})"

def _policy_findings(np) -> list[Finding]:
    out = []; rk = resource_key(np); spec = _spec(np); seen = set()
    def add(fid, sev, title, ev, rec):
        if (fid, ev) not in seen:
            seen.add((fid, ev)); out.append(_f(fid, sev, "network", title, rk, ev, rec))
    def ipblocks(peers, direction):
        for peer in peers:
            ib = _dict(peer).get("ipBlock")
            if not isinstance(ib, dict): continue
            issue = _cidr_issue(ib.get("cidr"))
            if issue == "any":
                exc = f" (except {ib['except']})" if ib.get("except") else ""
                if direction == "egress":
                    add("KF-NET-020", "medium", "Egress to any destination allowed", f"egress ipBlock cidr={ib.get('cidr')}{exc}",
                        "Restrict egress to required CIDRs, namespaces or pods and ports.")
                else:
                    add("KF-NET-021", "medium", "Ingress from any source allowed", f"ingress ipBlock cidr={ib.get('cidr')}{exc}",
                        "Restrict ingress to specific CIDRs, namespaces or pods.")
            elif issue == "wide":
                add("KF-NET-022", "low", "ipBlock is overly wide", f"{direction} ipBlock cidr={ib.get('cidr')}", "Narrow the CIDR to the actual range.")
    for i, rule in enumerate(_list(spec.get("egress"))):
        rule = _dict(rule); peers = rule.get("to")
        if not peers:
            add("KF-NET-020", "medium", "Egress to any destination allowed", f"egress[{i}] has no 'to' peers" + _ports_text(rule),
                "Restrict egress to required CIDRs, namespaces or pods and ports.")
        else:
            ipblocks(_list(peers), "egress")
            if any(p == {} for p in _list(peers)):
                add("KF-NET-020", "medium", "Egress to any destination allowed", f"egress[{i}] has an empty peer", "Specify the destinations.")
    for i, rule in enumerate(_list(spec.get("ingress"))):
        rule = _dict(rule); peers = rule.get("from")
        if not peers:
            add("KF-NET-030", "medium", "Allow-all ingress peer", f"ingress[{i}] has no 'from' peers" + _ports_text(rule),
                "Specify podSelector/namespaceSelector labels or ipBlock sources.")
        else:
            ipblocks(_list(peers), "ingress")
            for peer in _list(peers):
                peer = _dict(peer)
                if peer == {}:
                    add("KF-NET-030", "medium", "Allow-all ingress peer", f"ingress[{i}] has an empty peer", "Specify the allowed sources.")
                elif "namespaceSelector" in peer and "podSelector" not in peer and "ipBlock" not in peer and _empty_selector(peer["namespaceSelector"]):
                    add("KF-NET-030", "medium", "Allow-all ingress peer", f"ingress[{i}] namespaceSelector: {{}} admits every namespace",
                        "Select specific namespaces by label.")
    return out

def _network_findings(resources) -> list[Finding]:
    from .engine import _pod_spec, _selector_labels, _selector_matches, WORKLOAD_KINDS
    nps = [o for o in resources if o.get("kind") == "NetworkPolicy" and isinstance(o.get("spec"), dict)]
    out = []
    for np in nps: out += _policy_findings(np)
    wl_by_ns: dict[str, list] = {}
    for o in resources:
        if o.get("kind") in WORKLOAD_KINDS and _pod_spec(o)[0] is not None and _ns(o) not in SYSTEM_NAMESPACES:
            wl_by_ns.setdefault(_ns(o), []).append(o)
    for ns in sorted(wl_by_ns):
        pols = [p for p in nps if _ns(p) == ns]
        deny_in = any(_empty_selector(_spec(p).get("podSelector")) and "Ingress" in _np_types(_spec(p)) and not _spec(p).get("ingress") for p in pols)
        deny_eg = any(_empty_selector(_spec(p).get("podSelector")) and "Egress" in _np_types(_spec(p)) and not _spec(p).get("egress") for p in pols)
        names = ", ".join(sorted((o.get("metadata") or {}).get("name", "?") for o in wl_by_ns[ns]))
        if not deny_in:
            out.append(_f("KF-NET-010", "low", "network", "Namespace has no default-deny ingress policy", f"Namespace/{ns}",
                          f"no NetworkPolicy with an empty podSelector and policyTypes Ingress without rules; workloads: {names}",
                          "Add a default-deny ingress NetworkPolicy (podSelector: {}, policyTypes: [Ingress]) and allow only required traffic."))
        if not deny_eg:
            out.append(_f("KF-NET-011", "info", "network", "Namespace has no default-deny egress policy", f"Namespace/{ns}",
                          f"no default-deny egress NetworkPolicy; workloads: {names}",
                          "Add a default-deny egress NetworkPolicy and allow DNS plus required destinations."))
        if pols and not deny_in:
            for o in wl_by_ns[ns]:
                labels = _selector_labels(o)
                if not any(_selector_matches(_spec(p).get("podSelector") or {}, labels) for p in pols):
                    out.append(_f("KF-NET-012", "low", "network", "Workload selected by no NetworkPolicy", resource_key(o),
                                  f"namespace {ns} has NetworkPolicies but none selects this workload's Pod labels",
                                  "Add a policy that selects the workload, or a namespace default-deny."))
    return out

# -------------------------------------------------------------------- entry

def posture_findings(resources: list[dict[str, Any]]) -> list[Finding]:
    from .engine import _pod_spec
    resources = [o for o in resources if isinstance(o, dict) and o.get("kind")]
    sa_no_mount = {(_ns(o), (o.get("metadata") or {}).get("name")) for o in resources
                   if o.get("kind") == "ServiceAccount" and o.get("automountServiceAccountToken") is False}
    hpa = _hpa_min(resources)
    out: list[Finding] = []
    for o in resources:
        pod, _ = _pod_spec(o)
        if pod is None: continue
        rk = resource_key(o)
        out += _container_findings(o, pod, rk, sa_no_mount)
        out += _strategy_findings(o, rk)
    out += _availability_findings(resources, hpa)
    out += _network_findings(resources)
    return out
