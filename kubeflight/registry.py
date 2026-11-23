# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Registry of every finding id KubeFlight can emit, with rationale and remediation.

``severity`` is the typical/default severity; a few checks adjust it with context
(for example KF-EXP-001 is ``high`` only for an unrestricted LoadBalancer).
"""
from __future__ import annotations
from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# GitHub code-scanning security-severity scores (0.0-10.0).
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.5"}

PSS = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
SC = "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"
NP = "https://kubernetes.io/docs/concepts/services-networking/network-policies/"
RES = "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
PROBE = "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"
PDBREF = "https://kubernetes.io/docs/tasks/run-application/configure-pdb/"
RBACREF = "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
SVCREF = "https://kubernetes.io/docs/concepts/services-networking/service/"
DEPREF = "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    rationale: str
    fix: str
    reference: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "title": self.title, "severity": self.severity, "category": self.category,
                "rationale": self.rationale, "fix": self.fix, "reference": self.reference}


_RULES: list[Rule] = [
    Rule("KF-MAN-001", "Malformed Kubernetes object", "critical", "manifest",
         "apiVersion, kind and metadata.name are required; the API server rejects the object.", "Fix the manifest structure.", "https://kubernetes.io/docs/concepts/overview/working-with-objects/"),
    Rule("KF-MAN-010", "Workload requires spec.selector and spec.template", "critical", "schema",
         "Apps/Batch workloads without a selector and Pod template are rejected at admission.", "Add a selector and a Pod template that satisfy the API schema.", DEPREF),
    Rule("KF-MAN-011", "Workload selector does not match Pod template labels", "critical", "schema",
         "A selector that does not match the template labels is rejected, and would orphan Pods if it were not.", "Make spec.selector.matchLabels a subset of spec.template.metadata.labels.", DEPREF),
    Rule("KF-MAN-012", "Service ports must be a list", "critical", "schema", "spec.ports must be a list of port objects.", "Use the Service v1 schema.", SVCREF),
    Rule("KF-MAN-013", "NetworkPolicy should use networking.k8s.io/v1", "high", "schema", "Older NetworkPolicy API versions are not served.", "Use apiVersion networking.k8s.io/v1.", NP),
    Rule("KF-UPG-001", "Removed API version", "critical", "upgrade", "The apiVersion is no longer served by current Kubernetes; apply fails.", "Migrate the resource to its supported stable API before deployment.", "https://kubernetes.io/docs/reference/using-api/deprecation-guide/"),
    Rule("KF-UPG-010", "API removed in the target Kubernetes version", "critical", "upgrade", "The apiVersion/kind is no longer served at or before --target-kubernetes; apply fails.", "Migrate to the replacement API listed in the finding before upgrading.", "https://kubernetes.io/docs/reference/using-api/deprecation-guide/"),
    Rule("KF-UPG-011", "API deprecated in the target Kubernetes version", "medium", "upgrade", "The apiVersion/kind is deprecated and will be removed in a later release.", "Move to the replacement API now to avoid a forced migration.", "https://kubernetes.io/docs/reference/using-api/deprecation-guide/"),
    Rule("KF-FLD-001", "Unknown field in manifest", "medium", "schema", "A misspelled or unsupported field is silently dropped by the API server, so the intended setting never applies.", "Fix the field name (see the suggestion) or remove it.", "https://kubernetes.io/docs/reference/kubernetes-api/"),
    Rule("KF-FLD-002", "Field has the wrong type", "high", "schema", "A value of the wrong type is rejected by the API server or coerced unexpectedly.", "Use the documented type (for example an integer for replicas, strings for ConfigMap data).", "https://kubernetes.io/docs/reference/kubernetes-api/"),
    Rule("KF-CUS-900", "Custom rule could not be evaluated", "medium", "custom", "A user-defined rule failed on this resource (type error, limit exceeded), so its verdict is unknown.", "Fix the rule expression or guard it with exists().", "docs/CUSTOM_RULES.md"),
    Rule("KF-STO-001", "StorageClass not found in target snapshot", "high", "storage", "A PVC referencing a missing StorageClass stays Pending and blocks the Pods that mount it.", "Create or select a StorageClass available in the target cluster.", "https://kubernetes.io/docs/concepts/storage/storage-classes/"),
    Rule("KF-STO-010", "PVC shrink is unsupported", "critical", "storage", "Kubernetes cannot shrink a PersistentVolumeClaim; the update is rejected.", "Restore into a new, smaller volume instead.", "https://kubernetes.io/docs/concepts/storage/persistent-volumes/#expanding-persistent-volumes-claims"),
    Rule("KF-RES-001", "Invalid Kubernetes resource quantity", "critical", "resources", "An unparsable quantity is rejected by the API server; KubeFlight never treats it as zero.", "Use a valid Kubernetes Quantity (for example 500m, 256Mi).", "https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/"),
    Rule("KF-RBAC-001", "ServiceAccount not present in bundle or target snapshot", "low", "rbac", "Pods referencing a missing ServiceAccount are not created.", "Include the ServiceAccount in the release or create it in the target cluster.", RBACREF),
    Rule("KF-RBAC-010", "Required permission not proven", "high", "rbac", "The workload declares a permission contract that no submitted Role/Binding grants.", "Grant the permission with a narrowly scoped Role and binding.", RBACREF),
    Rule("KF-RBAC-020", "Role grants wildcard access", "high", "rbac", "Wildcard verbs/resources grant far more than needed and widen the blast radius of a compromised workload.", "List the specific verbs and resources the workload needs.", RBACREF),
    Rule("KF-RBAC-021", "Binding grants cluster-admin", "critical", "rbac", "cluster-admin gives unrestricted control of the cluster.", "Bind a narrowly scoped role instead.", RBACREF),
    Rule("KF-RBAC-022", "Binding grants access to anonymous users", "critical", "rbac", "Anyone, including unauthenticated callers, would receive the role.", "Never bind roles to system:anonymous or system:unauthenticated.", RBACREF),
    Rule("KF-PSS-001", "Host namespace sharing", "critical", "security", "hostNetwork/hostPID/hostIPC expose node-level namespaces and violate Baseline and Restricted Pod Security.", "Disable host namespace sharing.", PSS),
    Rule("KF-PSS-002", "hostPath volume", "high", "security", "hostPath mounts expose the node filesystem and violate Restricted Pod Security.", "Use a PVC, projected, configMap, secret or emptyDir volume.", PSS),
    Rule("KF-PSS-003", "Unsafe sysctl", "high", "security", "Sysctls outside the safe set can destabilize the node or other Pods.", "Remove the sysctl or isolate the workload on dedicated nodes.", PSS),
    Rule("KF-PSS-004", "Pod SELinux options violate Restricted policy", "high", "security", "Custom SELinux user/role/type may weaken isolation.", "Use an allowed SELinux type and do not set user/role.", PSS),
    Rule("KF-PSS-005", "AppArmor annotation violates Restricted policy", "high", "security", "Unconfined or custom AppArmor profiles weaken isolation.", "Use runtime/default or a localhost profile.", PSS),
    Rule("KF-PSS-006", "Windows HostProcess enabled", "critical", "security", "HostProcess containers run directly on the node.", "Disable windowsOptions.hostProcess.", PSS),
    Rule("KF-PSS-007", "Probe host field set", "high", "security", "A probe host field can be abused to probe other hosts (SSRF-style).", "Remove the explicit host field.", PSS),
    Rule("KF-PSS-008", "Lifecycle host field set", "high", "security", "A lifecycle hook host field can be abused to reach other hosts.", "Remove the explicit host field.", PSS),
    Rule("KF-PSS-009", "Container explicitly runs as UID 0", "high", "security", "Running as root increases the impact of container escapes.", "Use a non-zero runAsUser.", PSS),
    Rule("KF-PSS-010", "Container AppArmor profile violates Restricted policy", "high", "security", "Unconfined or custom AppArmor profiles weaken isolation.", "Use RuntimeDefault or Localhost.", PSS),
    Rule("KF-PSS-011", "Container SELinux options violate Restricted policy", "high", "security", "Custom SELinux user/role/type may weaken isolation.", "Use an allowed SELinux type and do not set user/role.", PSS),
    Rule("KF-SEC-010", "Non-root execution not proven", "high", "security", "Without runAsNonRoot or a non-zero runAsUser the image may run as root.", "Set runAsNonRoot: true or a non-zero runAsUser.", SC),
    Rule("KF-SEC-011", "Seccomp profile missing or invalid", "high", "security", "Without a seccomp profile the container runs unconfined and can use any syscall.", "Set seccompProfile.type: RuntimeDefault (pod or container level).", SC),
    Rule("KF-SEC-020", "Privileged container", "critical", "security", "Privileged containers have nearly full access to the host.", "Remove privileged mode.", SC),
    Rule("KF-SEC-021", "Privilege escalation not disabled", "high", "security", "Processes may gain more privileges than their parent (setuid binaries).", "Set allowPrivilegeEscalation: false.", SC),
    Rule("KF-SEC-022", "Capabilities violate Restricted policy", "high", "security", "Extra Linux capabilities widen what a compromised process can do.", "Drop ALL and add back only NET_BIND_SERVICE when required.", SC),
    Rule("KF-SEC-023", "Writable root filesystem", "low", "security", "A writable root filesystem lets attackers persist tools or tamper with binaries.", "Set readOnlyRootFilesystem: true and mount emptyDir for scratch paths.", SC),
    Rule("KF-SEC-030", "ServiceAccount token auto-mounted", "low", "security", "Pods using the default ServiceAccount (or any SA) mount an API token by default; most apps never call the API, and a stolen token is an attack path.", "Set automountServiceAccountToken: false on the Pod spec or the ServiceAccount, and use a dedicated ServiceAccount when API access is needed.", "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"),
    Rule("KF-SEC-031", "hostPort used", "high", "security", "hostPort binds a node port, bypasses NetworkPolicy and Service abstractions, limits scheduling and violates Baseline Pod Security.", "Expose the container through a Service (ClusterIP/NodePort/LoadBalancer) instead.", PSS),
    Rule("KF-SEC-032", "Privileged port without NET_BIND_SERVICE", "low", "security", "Binding a port below 1024 as non-root fails on runtimes that keep net.ipv4.ip_unprivileged_port_start=1024, causing CrashLoopBackOff.", "Listen on a port >= 1024 (remap with the Service) or add NET_BIND_SERVICE after dropping ALL.", SC),
    Rule("KF-SUP-001", "Unpinned image", "medium", "supply-chain", "Mutable tags (or no tag) make rollouts non-reproducible and unreviewable.", "Pin an immutable digest or explicit version tag.", "https://kubernetes.io/docs/concepts/containers/images/"),
    Rule("KF-SUP-900", "Suppression has expired", "low", "suppression", "An ignore entry past its expiry no longer hides the finding.", "Fix the finding or renew the suppression with a new review.", ""),
    Rule("KF-SUP-901", "Critical findings need an expiry to be suppressed", "low", "suppression", "A permanent suppression of a critical finding is a standing blind spot.", "Add an expires date (YYYY-MM-DD).", ""),
    Rule("KF-REL-001", "Resource requests incomplete", "medium", "reliability", "Without CPU and memory requests the scheduler cannot place Pods sensibly and QoS is degraded.", "Set realistic CPU and memory requests.", RES),
    Rule("KF-REL-002", "Memory limit missing", "low", "reliability", "A container without a memory limit can consume node memory and trigger node-level OOM.", "Set a memory limit after validating workload behavior.", RES),
    Rule("KF-REL-003", "Readiness probe missing", "medium", "reliability", "Without a readiness probe traffic is sent to Pods before they can serve, and rollouts cannot detect bad versions.", "Add a readiness probe.", PROBE),
    Rule("KF-REL-004", "Liveness probe missing", "low", "reliability", "Hung processes are never restarted without a liveness probe.", "Add a liveness or startup probe suited to the application.", PROBE),
    Rule("KF-REL-005", "No resource requests or limits (BestEffort)", "medium", "reliability", "BestEffort Pods are the first evicted under node pressure and are unaccounted for by the scheduler.", "Set requests (and a memory limit) so the Pod is Burstable or Guaranteed.", RES),
    Rule("KF-REL-006", "Resource limit below request", "high", "reliability", "The API server rejects a limit that is lower than the request.", "Set limits >= requests.", RES),
    Rule("KF-REL-010", "Single replica behind a Service", "medium", "reliability", "A one-replica Deployment/StatefulSet serving a Service has downtime on every rollout, drain or node failure.", "Run at least 2 replicas (with anti-affinity or topology spread) or accept and document the downtime.", DEPREF),
    Rule("KF-REL-011", "PodDisruptionBudget blocks voluntary disruptions", "high", "reliability", "minAvailable equal to (or above) the replica count, or maxUnavailable 0, means node drains and cluster upgrades can never evict a Pod.", "Use minAvailable of replicas-1 or maxUnavailable: 1.", PDBREF),
    Rule("KF-REL-012", "RollingUpdate with maxUnavailable=0 and maxSurge=0", "critical", "reliability", "The API server rejects a rolling update that can neither surge nor make Pods unavailable.", "Allow at least one of maxSurge or maxUnavailable to be non-zero.", DEPREF),
    Rule("KF-REL-020", "HPA minReplicas exceeds maxReplicas", "critical", "reliability", "The HPA is invalid and will not scale.", "Set maxReplicas >= minReplicas.", "https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/"),
    Rule("KF-REL-021", "HPA cannot scale (min equals max)", "low", "reliability", "The HPA has no range to scale within.", "Widen the range or remove the HPA.", "https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/"),
    Rule("KF-ROL-001", "No matching PodDisruptionBudget", "low", "rollout", "Multi-replica Deployments without a PDB can lose all replicas during node drains.", "Add a PodDisruptionBudget.", PDBREF),
    Rule("KF-SCH-001", "Not all replicas can be placed", "critical", "scheduling", "Replicas that cannot be scheduled leave the rollout stuck or under capacity.", "Adjust requests, selectors, taints/tolerations, affinity or cluster capacity.", "https://kubernetes.io/docs/concepts/scheduling-eviction/"),
    Rule("KF-SCH-002", "All replicas collapse onto one node", "high", "scheduling", "A single node failure takes down every replica.", "Add topology spread or anti-affinity, or more capacity.", "https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/"),
    Rule("KF-NET-001", "NetworkPolicy blocks inferred path", "high", "network", "An inferred service dependency is statically denied by the submitted NetworkPolicies.", "Add a narrowly scoped policy rule for the source, destination and port.", NP),
    Rule("KF-NET-010", "Namespace has no default-deny ingress policy", "low", "network", "Without a default-deny ingress policy every Pod accepts traffic from any Pod in the cluster.", "Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress], then allow only required traffic.", NP),
    Rule("KF-NET-011", "Namespace has no default-deny egress policy", "info", "network", "Without a default-deny egress policy a compromised Pod can reach any destination.", "Add a NetworkPolicy with podSelector: {} and policyTypes: [Egress], then allow DNS and required destinations.", NP),
    Rule("KF-NET-012", "Workload selected by no NetworkPolicy", "low", "network", "The namespace uses NetworkPolicies but this workload is matched by none and no default-deny applies, so it is fully open.", "Add a policy selecting the workload's labels, or a namespace default-deny.", NP),
    Rule("KF-NET-020", "Egress to any destination allowed", "medium", "network", "An egress rule to 0.0.0.0/0, ::/0 or an empty rule allows exfiltration and reaching internal services.", "Restrict egress to required CIDRs, namespaces or pods and ports; use except lists for internal ranges.", NP),
    Rule("KF-NET-021", "Ingress from any source allowed", "medium", "network", "An ingress rule from 0.0.0.0/0 or ::/0 exposes the workload to any network source.", "Restrict ingress to specific CIDRs, namespaces or pods.", NP),
    Rule("KF-NET-022", "ipBlock is overly wide", "low", "network", "A very large CIDR (broader than /8 for IPv4, /32 for IPv6) allows far more than a typical dependency needs.", "Narrow the CIDR to the actual range.", NP),
    Rule("KF-NET-030", "Allow-all ingress peer", "medium", "network", "An ingress rule with no sources, an empty peer, or an empty namespaceSelector admits traffic from every Pod (or namespace) in the cluster.", "Specify podSelector/namespaceSelector labels or ipBlock sources.", NP),
    Rule("KF-EXP-001", "Service exposed externally", "high", "exposure", "LoadBalancer/NodePort Services are reachable from outside the cluster (high when a LoadBalancer has no loadBalancerSourceRanges, otherwise medium).", "Confirm exposure is intended; restrict loadBalancerSourceRanges or use an internal load balancer.", SVCREF),
    Rule("KF-EXP-002", "Ingress has no TLS configuration", "medium", "exposure", "Traffic to the Ingress is unencrypted.", "Terminate TLS on the Ingress with spec.tls and a certificate secret.", "https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"),
    Rule("KF-EXP-003", "Service uses externalIPs", "high", "exposure", "externalIPs can hijack cluster traffic (CVE-2020-8554 class).", "Prefer a LoadBalancer or Gateway.", SVCREF),
    Rule("KF-BLAST-001", "Wide dependency blast radius", "high", "blast-radius", "The change affects many dependent resources.", "Split the change, canary it, or add explicit rollout safeguards.", ""),
    Rule("KF-COST-001", "Estimated monthly cost rises >10%", "medium", "cost", "Requests/replicas grew noticeably relative to the baseline.", "Review requests/replicas or update the approved budget.", ""),
    Rule("KF-COST-002", "Estimated monthly cost rises >50%", "high", "cost", "Requests/replicas grew sharply relative to the baseline.", "Review requests/replicas or explicitly approve the budget increase.", ""),
]

REGISTRY: dict[str, Rule] = {r.id: r for r in _RULES}
assert len(REGISTRY) == len(_RULES), "duplicate rule id in registry"


def get_rule(rule_id: str) -> Rule | None:
    return REGISTRY.get(str(rule_id).strip().upper())


def format_rule(r: Rule) -> str:
    lines = [f"{r.id}  {r.title}", f"Severity:  {r.severity}", f"Category:  {r.category}", "",
             "Why it matters:", f"  {r.rationale}", "", "How to fix:", f"  {r.fix}"]
    if r.reference:
        lines += ["", f"Reference: {r.reference}"]
    return "\n".join(lines) + "\n"
