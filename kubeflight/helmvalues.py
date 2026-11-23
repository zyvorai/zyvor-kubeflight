# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Hygiene checks on a raw Helm values.yaml. Charts are never rendered; secret values are never printed."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any
import yaml
from .images import FLOATING_TAGS, _sanitize
from .models import Finding

MAX_FILE_BYTES = 512 * 1024
MAX_NODES = 50_000
MAX_DEPTH = 40
MAX_FILES = 50

DEFAULT_SECRETS = frozenset({"admin", "administrator", "password", "passw0rd", "changeme", "change-me", "changeit", "secret", "root", "toor", "123456",
                             "12345678", "qwerty", "test", "default", "guest", "letmein", "welcome", "postgres", "mysql", "redis", "mongo",
                             "minio", "minioadmin", "pass", "demo", "example", "s3cret", "supersecret", "p@ssw0rd"})
_CRED_KEY = re.compile(r"(password|passwd|pwd|secret|token|apikey|credentials?)$")
_BOOL_TRUE = {"true", "yes", "on", "y"}
# truthy -> unsafe
_PRIV_KEYS = {"privileged": True, "allowprivilegeescalation": True, "hostpid": True, "hostipc": True, "runasnonroot": False}


class _Node:
    """A scalar/mapping/sequence walker over the composed YAML tree (keeps line numbers, no object construction)."""
    __slots__ = ("loader", "budget", "seen")

    def __init__(self, loader):
        self.loader, self.budget, self.seen = loader, MAX_NODES, set()


def _scalar(node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        tag = node.tag.rsplit(":", 1)[-1]
        v = node.value
        if tag == "bool":
            return v.strip().lower() in _BOOL_TRUE
        if tag == "int":
            try:
                return int(v.replace("_", ""), 0)
            except ValueError:
                return v
        if tag == "null":
            return None
        return v
    return node


def _walk(node: yaml.Node, path: str, state: _Node, out: list[tuple[str, yaml.Node, yaml.Node | None]], depth: int = 0, key_node: yaml.Node | None = None) -> None:
    """Collect (path, node, key_node) for every node, guarding against alias bombs and deep nesting."""
    state.budget -= 1
    if state.budget < 0:
        raise ValueError("values file has too many nodes (possible alias expansion)")
    if depth > MAX_DEPTH:
        raise ValueError("values file is nested too deeply")
    out.append((path, node, key_node))
    if isinstance(node, (yaml.MappingNode, yaml.SequenceNode)):
        # an anchor reused many times would be walked once per use: bound that by the node budget above
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                kname = _sanitize(k.value if isinstance(k, yaml.ScalarNode) else "?", 80)
                _walk(v, f"{path}.{kname}" if path else kname, state, out, depth + 1, k)
        else:
            for i, v in enumerate(node.value):
                _walk(v, f"{path}[{i}]", state, out, depth + 1, None)


def _children(node: yaml.Node) -> dict[str, yaml.Node]:
    if not isinstance(node, yaml.MappingNode):
        return {}
    return {str(k.value): v for k, v in node.value if isinstance(k, yaml.ScalarNode)}


def _empty(node: yaml.Node | None) -> bool:
    if node is None:
        return True
    if isinstance(node, yaml.MappingNode) or isinstance(node, yaml.SequenceNode):
        return not node.value
    return _scalar(node) in (None, "", "~")


def values_findings(text: str, source: str = "values.yaml") -> tuple[list[Finding], dict[str, tuple[str, int]]]:
    """Return (findings, locations) for one values document. ``source`` is only a label/path."""
    if len(text.encode("utf-8", "ignore")) > MAX_FILE_BYTES:
        raise ValueError(f"{source}: values file is larger than {MAX_FILE_BYTES // 1024} KiB")
    name = Path(source).name
    findings: list[Finding] = []
    locs: dict[str, tuple[str, int]] = {}
    loader = yaml.SafeLoader(text)
    try:
        try:
            docs = []
            while loader.check_node():
                docs.append(loader.get_node())
                if len(docs) > 20:
                    raise ValueError(f"{source}: too many YAML documents")
        except yaml.YAMLError as e:
            raise ValueError(f"{source}: invalid YAML: {_sanitize(e)}") from e
    finally:
        loader.dispose()

    def add(fid, sev, cat, title, path, node, evidence, rec):
        res = f"Values/{name}:{path or '.'}"
        findings.append(Finding(fid, sev, cat, title, res, evidence, rec))
        locs.setdefault(res, (source, node.start_mark.line + 1))

    for doc in docs:
        if not isinstance(doc, yaml.MappingNode):
            continue
        state = _Node(loader)
        nodes: list[tuple[str, yaml.Node, yaml.Node | None]] = []
        _walk(doc, "", state, nodes)
        for path, node, knode in nodes:
            key = (knode.value if isinstance(knode, yaml.ScalarNode) else "").strip()
            lk = key.lower()
            kids = _children(node)
            val = _scalar(node) if isinstance(node, yaml.ScalarNode) else None
            at = knode or node
            # KF-HLM-001 / 002: boolean flags
            if isinstance(node, yaml.ScalarNode) and lk in _PRIV_KEYS and isinstance(val, bool) and val is _PRIV_KEYS[lk]:
                add("KF-HLM-001", "high", "helm-values", f"Values enable privileged or root execution: {key}", path, at, f"{path} is {str(val).lower()}",
                    "Remove the flag or set it to the safe value; grant individual capabilities instead.")
            elif isinstance(node, yaml.ScalarNode) and lk == "runasuser" and val == 0 and not isinstance(val, bool):
                add("KF-HLM-001", "high", "helm-values", "Values run the container as UID 0", path, at, f"{path} is 0", "Use a non-root UID.")
            if isinstance(node, yaml.ScalarNode) and lk == "hostnetwork" and val is True:
                add("KF-HLM-002", "high", "helm-values", "Values enable hostNetwork", path, at, f"{path} is true", "Remove hostNetwork or set it to false.")
            # KF-HLM-003: latest tags
            if lk == "tag" and isinstance(node, yaml.ScalarNode) and isinstance(val, str) and val.strip().lower() == "latest":
                add("KF-HLM-003", "medium", "helm-values", "Values use the latest image tag", path, at, f"{path} is 'latest'", "Set an explicit version tag, ideally with a digest.")
            elif lk in {"image", "repository"} and isinstance(val, str) and re.search(r":latest(@|$)", val.strip()):
                add("KF-HLM-003", "medium", "helm-values", "Values use the latest image tag", path, at, f"{path} ends in :latest", "Set an explicit version tag.")
            elif lk == "tag" and isinstance(val, str) and val.strip().lower() in FLOATING_TAGS:
                add("KF-HLM-003", "medium", "helm-values", "Values use a mutable image tag", path, at, f"{path} is the moving tag {_sanitize(val, 40)!r}", "Set an explicit version tag.")
            # KF-HLM-004: resources
            if lk == "resources" and isinstance(node, (yaml.MappingNode,)):
                req = kids.get("requests")
                if _empty(node) or _empty(req) or any(_empty(v) for v in _children(req).values()):
                    add("KF-HLM-004", "medium", "helm-values", "Values leave resource requests empty", path, at,
                        f"{path} has no complete requests", "Set cpu and memory requests and a memory limit.")
            # KF-HLM-005: ingress without TLS
            if lk == "ingress" and isinstance(node, yaml.MappingNode):
                en = kids.get("enabled")
                if en is not None and _scalar(en) is True and _empty(kids.get("tls")):
                    add("KF-HLM-005", "medium", "helm-values", "Values enable an ingress without TLS", path, at, f"{path}.enabled is true and {path}.tls is empty",
                        "Add ingress.tls with a certificate secret.")
            # KF-HLM-006/007: credentials by key name only
            if isinstance(node, yaml.ScalarNode) and isinstance(val, (str, int)) and not isinstance(val, bool) and str(val).strip():
                nk = re.sub(r"[-_ ]", "", lk)
                sval = str(val).strip()
                if _CRED_KEY.search(nk) and not nk.startswith("existing") and not re.search(r"\{\{|\$\(|\$\{|^<.*>$|^\$[A-Za-z_]", sval) and node.tag.endswith(("str", "int")):
                    if sval.lower() in DEFAULT_SECRETS:
                        add("KF-HLM-006", "high", "helm-values", f"Default or well-known password in values: {key}", path, at,
                            f"{path} is set to a well-known default (value not shown)", "Use an existing Secret, a generated value or an external secret manager.")
                    else:
                        add("KF-HLM-007", "medium", "helm-values", f"Hard-coded secret in values: {key}", path, at,
                            f"{path} holds a literal value (value not shown)", "Reference an existing Secret or inject the value at deploy time.")
    return findings, locs


def find_values_files(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            raise ValueError(f"Path does not exist: {p}")
        if p.is_dir():
            found = sorted(x for x in p.glob("values*.y*ml") if x.is_file())
            if not found:
                raise ValueError(f"No values*.yaml found in {p}")
            out += found
        else:
            out.append(p)
    if len(out) > MAX_FILES:
        raise ValueError(f"more than {MAX_FILES} values files")
    return out


def load_values(paths: list[str]) -> tuple[list[Finding], dict[str, tuple[str, int]], int]:
    files = find_values_files(paths)
    findings: list[Finding] = []
    locs: dict[str, tuple[str, int]] = {}
    for f in files:
        if f.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{f.name}: values file is larger than {MAX_FILE_BYTES // 1024} KiB")
        fi, lo = values_findings(f.read_text(encoding="utf-8"), str(f))
        findings += fi
        locs.update(lo)
    return findings, locs, len(files)
