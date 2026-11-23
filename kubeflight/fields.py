# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Offline field/type validation for core Kubernetes kinds.

Embedded, hand-curated field tables (derived from the Kubernetes OpenAPI types)
catch typos such as ``replica:`` or ``containerport:`` and wrong scalar types
such as a numeric ConfigMap value, without a cluster or network access.
Deep or rarely used sub-objects are typed ``any`` (accepted as-is) on purpose:
an incomplete table must never produce a false "unknown field".
Kinds not listed here (CRDs, unknown groups) are skipped.

Findings: KF-FLD-001 unknown field (medium), KF-FLD-002 wrong type (high).
"""
from __future__ import annotations
import difflib
from typing import Any
from .models import Finding
from .parser import resource_key

# Type vocabulary: "str" "int" "bool" "any" "qty" (quantity) "ios" (int-or-string)
# "strmap" (map[string]string) "qmap" (map[string]quantity); ("list", T);
# dict = nested object schema; "$Name" = shared schema.
def _l(t): return ("list", t)

SHARED: dict[str, dict[str, Any]] = {
 "ObjectMeta": {"name":"str","generateName":"str","namespace":"str","labels":"strmap","annotations":"strmap","uid":"str",
   "resourceVersion":"str","generation":"int","creationTimestamp":"any","deletionTimestamp":"any","deletionGracePeriodSeconds":"int",
   "ownerReferences":"any","finalizers":_l("str"),"managedFields":"any","selfLink":"str"},
 "LabelSelector": {"matchLabels":"strmap","matchExpressions":_l({"key":"str","operator":"str","values":_l("str")})},
 "Probe": {"exec":"any","httpGet":"any","tcpSocket":"any","grpc":"any","initialDelaySeconds":"int","timeoutSeconds":"int",
   "periodSeconds":"int","successThreshold":"int","failureThreshold":"int","terminationGracePeriodSeconds":"int"},
 "SecCtx": {"allowPrivilegeEscalation":"bool","capabilities":{"add":_l("str"),"drop":_l("str")},"privileged":"bool","procMount":"str",
   "readOnlyRootFilesystem":"bool","runAsGroup":"int","runAsNonRoot":"bool","runAsUser":"int","seLinuxOptions":"any",
   "seccompProfile":"any","windowsOptions":"any","appArmorProfile":"any"},
 "PodSecCtx": {"fsGroup":"int","fsGroupChangePolicy":"str","runAsGroup":"int","runAsNonRoot":"bool","runAsUser":"int",
   "seLinuxOptions":"any","seLinuxChangePolicy":"str","seccompProfile":"any","supplementalGroups":_l("int"),
   "supplementalGroupsPolicy":"str","sysctls":"any","windowsOptions":"any","appArmorProfile":"any"},
 "Container": {"name":"str","image":"str","command":_l("str"),"args":_l("str"),"workingDir":"str",
   "ports":_l({"name":"str","containerPort":"int","hostPort":"int","hostIP":"str","protocol":"str"}),
   "envFrom":"any","env":_l({"name":"str","value":"str","valueFrom":"any"}),
   "resources":{"limits":"qmap","requests":"qmap","claims":"any"},"resizePolicy":"any","restartPolicy":"str",
   "volumeMounts":_l({"name":"str","mountPath":"str","subPath":"str","subPathExpr":"str","readOnly":"bool","mountPropagation":"str","recursiveReadOnly":"str"}),
   "volumeDevices":"any","livenessProbe":"$Probe","readinessProbe":"$Probe","startupProbe":"$Probe","lifecycle":"any",
   "terminationMessagePath":"str","terminationMessagePolicy":"str","imagePullPolicy":"str","securityContext":"$SecCtx",
   "stdin":"bool","stdinOnce":"bool","tty":"bool"},
 "PodSpec": {"containers":_l("$Container"),"initContainers":_l("$Container"),"ephemeralContainers":"any","volumes":"any",
   "restartPolicy":"str","terminationGracePeriodSeconds":"int","activeDeadlineSeconds":"int","dnsPolicy":"str","dnsConfig":"any",
   "nodeSelector":"strmap","serviceAccountName":"str","serviceAccount":"str","automountServiceAccountToken":"bool","nodeName":"str",
   "hostNetwork":"bool","hostPID":"bool","hostIPC":"bool","shareProcessNamespace":"bool","hostUsers":"bool","securityContext":"$PodSecCtx",
   "imagePullSecrets":"any","hostname":"str","hostnameOverride":"str","subdomain":"str","affinity":"any","schedulerName":"str",
   "tolerations":"any","hostAliases":"any","priorityClassName":"str","priority":"int","readinessGates":"any","runtimeClassName":"str",
   "enableServiceLinks":"bool","preemptionPolicy":"str","overhead":"qmap","topologySpreadConstraints":"any","setHostnameAsFQDN":"bool",
   "os":"any","schedulingGates":"any","resourceClaims":"any","resources":"any"},
 "PodTemplate": {"metadata":"$ObjectMeta","spec":"$PodSpec"},
 "JobSpec": {"parallelism":"int","completions":"int","activeDeadlineSeconds":"int","backoffLimit":"int","selector":"$LabelSelector",
   "manualSelector":"bool","template":"$PodTemplate","ttlSecondsAfterFinished":"int","completionMode":"str","suspend":"bool",
   "podFailurePolicy":"any","successPolicy":"any","backoffLimitPerIndex":"int","maxFailedIndexes":"int","podReplacementPolicy":"str","managedBy":"str"},
}

_TOP = {"apiVersion":"str","kind":"str","metadata":"$ObjectMeta","status":"any"}
def _kind(groups, **fields): return (set(groups.split()), {**_TOP, **fields})
def _spec(**f): return {"spec": f}

KINDS: dict[str, tuple[set[str], dict[str, Any]]] = {
 "Pod": _kind("v1", **_spec(**SHARED["PodSpec"])),
 "Deployment": _kind("apps/v1", **_spec(replicas="int",selector="$LabelSelector",template="$PodTemplate",strategy="any",
        minReadySeconds="int",revisionHistoryLimit="int",paused="bool",progressDeadlineSeconds="int")),
 "StatefulSet": _kind("apps/v1", **_spec(replicas="int",selector="$LabelSelector",template="$PodTemplate",volumeClaimTemplates="any",
        serviceName="str",podManagementPolicy="str",updateStrategy="any",revisionHistoryLimit="int",minReadySeconds="int",
        persistentVolumeClaimRetentionPolicy="any",ordinals="any")),
 "DaemonSet": _kind("apps/v1", **_spec(selector="$LabelSelector",template="$PodTemplate",updateStrategy="any",
        minReadySeconds="int",revisionHistoryLimit="int")),
 "Job": _kind("batch/v1", **_spec(**SHARED["JobSpec"])),
 "CronJob": _kind("batch/v1", **_spec(schedule="str",timeZone="str",startingDeadlineSeconds="int",concurrencyPolicy="str",suspend="bool",
        jobTemplate={"metadata":"$ObjectMeta","spec":"$JobSpec"},successfulJobsHistoryLimit="int",failedJobsHistoryLimit="int")),
 "Service": _kind("v1", **_spec(ports=_l({"name":"str","protocol":"str","appProtocol":"str","port":"int","targetPort":"ios","nodePort":"int"}),
        selector="strmap",clusterIP="str",clusterIPs=_l("str"),type="str",externalIPs=_l("str"),sessionAffinity="str",loadBalancerIP="str",
        loadBalancerSourceRanges=_l("str"),externalName="str",externalTrafficPolicy="str",healthCheckNodePort="int",
        publishNotReadyAddresses="bool",sessionAffinityConfig="any",ipFamilies=_l("str"),ipFamilyPolicy="str",
        allocateLoadBalancerNodePorts="bool",loadBalancerClass="str",internalTrafficPolicy="str",trafficDistribution="str")),
 "Ingress": _kind("networking.k8s.io/v1", **_spec(ingressClassName="str",defaultBackend="any",tls=_l({"hosts":_l("str"),"secretName":"str"}),rules="any")),
 "ConfigMap": _kind("v1", data="strmap", binaryData="strmap", immutable="bool"),
 "Secret": _kind("v1", data="strmap", stringData="strmap", type="str", immutable="bool"),
 "ServiceAccount": _kind("v1", secrets="any", imagePullSecrets="any", automountServiceAccountToken="bool"),
 "PersistentVolumeClaim": _kind("v1", **_spec(accessModes=_l("str"),selector="$LabelSelector",resources={"requests":"qmap","limits":"qmap"},
        volumeName="str",storageClassName="str",volumeMode="str",dataSource="any",dataSourceRef="any",volumeAttributesClassName="str")),
 "HorizontalPodAutoscaler": _kind("autoscaling/v2 autoscaling/v1 autoscaling/v2beta2 autoscaling/v2beta1", **_spec(scaleTargetRef="any",
        minReplicas="int",maxReplicas="int",metrics="any",behavior="any",targetCPUUtilizationPercentage="int")),
 "NetworkPolicy": _kind("networking.k8s.io/v1", **_spec(podSelector="$LabelSelector",ingress="any",egress="any",policyTypes=_l("str"))),
 "PodDisruptionBudget": _kind("policy/v1", **_spec(minAvailable="ios",maxUnavailable="ios",selector="$LabelSelector",unhealthyPodEvictionPolicy="str")),
 "Role": _kind("rbac.authorization.k8s.io/v1", rules=_l({"apiGroups":_l("str"),"resources":_l("str"),"resourceNames":_l("str"),"verbs":_l("str"),"nonResourceURLs":_l("str")})),
 "ClusterRole": _kind("rbac.authorization.k8s.io/v1", aggregationRule="any", rules=_l({"apiGroups":_l("str"),"resources":_l("str"),"resourceNames":_l("str"),"verbs":_l("str"),"nonResourceURLs":_l("str")})),
 "RoleBinding": _kind("rbac.authorization.k8s.io/v1", subjects=_l({"kind":"str","apiGroup":"str","name":"str","namespace":"str"}), roleRef={"apiGroup":"str","kind":"str","name":"str"}),
 "ClusterRoleBinding": _kind("rbac.authorization.k8s.io/v1", subjects=_l({"kind":"str","apiGroup":"str","name":"str","namespace":"str"}), roleRef={"apiGroup":"str","kind":"str","name":"str"}),
}

MAX_PER_RESOURCE = 20
_NAMES = {"str": "string", "int": "integer", "bool": "boolean", "qty": "quantity", "ios": "integer or string"}

def _ok(t: str, v: Any) -> bool:
    if t == "str": return isinstance(v, str)
    if t == "int": return isinstance(v, int) and not isinstance(v, bool)
    if t == "bool": return isinstance(v, bool)
    if t == "qty": return isinstance(v, (str, int, float)) and not isinstance(v, bool)
    if t == "ios": return isinstance(v, (str, int)) and not isinstance(v, bool)
    return True

def _tname(v: Any) -> str:
    return {"str":"string","int":"integer","bool":"boolean","float":"number","dict":"object","list":"list"}.get(type(v).__name__, type(v).__name__)

def _walk(t: Any, v: Any, path: str, out: list[tuple[str, str, str]], budget: list[int]) -> None:
    if v is None or t == "any" or budget[0] <= 0:
        return
    budget[0] -= 1
    if isinstance(t, str) and t.startswith("$"):
        t = SHARED[t[1:]]
    if isinstance(t, tuple):  # list
        if not isinstance(v, list):
            out.append(("type", path, f"expected list, got {_tname(v)}")); return
        for i, item in enumerate(v):
            _walk(t[1], item, f"{path}[{i}]", out, budget)
    elif isinstance(t, dict):
        if not isinstance(v, dict):
            out.append(("type", path, f"expected object, got {_tname(v)}")); return
        for k, sub in v.items():
            if k in t:
                _walk(t[k], sub, f"{path}.{k}" if path else str(k), out, budget)
            else:
                near = difflib.get_close_matches(str(k), list(t), n=1, cutoff=0.6)
                out.append(("unknown", f"{path}.{k}" if path else str(k), f"unknown field{'; did you mean ' + repr(near[0]) + '?' if near else ''}"))
    elif t in ("strmap", "qmap"):
        if not isinstance(v, dict):
            out.append(("type", path, f"expected map, got {_tname(v)}")); return
        want = "str" if t == "strmap" else "qty"
        for k, sub in v.items():
            if sub is not None and not _ok(want, sub):
                out.append(("type", f"{path}.{k}", f"expected {_NAMES[want]}, got {_tname(sub)} ({sub!r}); quote the value"))
    elif not _ok(t, v):
        hint = "; quote the value" if t == "str" and isinstance(v, (int, float, bool)) else ""
        out.append(("type", path, f"expected {_NAMES[t]}, got {_tname(v)} ({v!r}){hint}"))

def field_findings(resources: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    for o in resources:
        if not isinstance(o, dict):
            continue
        ent = KINDS.get(o.get("kind"))  # type: ignore[arg-type]
        if ent is None or o.get("apiVersion") not in ent[0]:
            continue
        rk = resource_key(o)
        issues: list[tuple[str, str, str]] = []
        _walk(ent[1], o, "", issues, [20000])
        for kind, path, msg in issues[:MAX_PER_RESOURCE]:
            if kind == "unknown":
                out.append(Finding("KF-FLD-001", "medium", "schema", f"Unknown field {path}", rk, f"{path}: {msg}",
                                   "Fix the field name; kubectl with strict validation rejects it and otherwise it is silently dropped."))
            else:
                out.append(Finding("KF-FLD-002", "high", "schema", f"Field {path} has the wrong type", rk, f"{path}: {msg}",
                                   "Use the type defined by the Kubernetes API schema."))
        if len(issues) > MAX_PER_RESOURCE:
            out.append(Finding("KF-FLD-001", "info", "schema", "More field problems omitted", rk, f"{len(issues) - MAX_PER_RESOURCE} further issue(s) not shown", "Fix the reported fields and re-run."))
    return out
