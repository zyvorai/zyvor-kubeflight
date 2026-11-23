# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""Image reference parsing and registry-free hygiene checks (digest pinning, mutable tags, registry allow-list)."""
from __future__ import annotations
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import yaml
from .engine import _pod_spec
from .models import Finding
from .parser import resource_key

MAX_POLICY_BYTES = 64 * 1024
MAX_IMAGE_LEN = 512
DOCKER_HUB = "docker.io"
# Tags that name a moving target rather than a release. ``latest`` / missing tag is KF-SUP-001's job.
FLOATING_TAGS = frozenset({"stable", "edge", "main", "master", "dev", "develop", "devel", "nightly", "canary", "current",
                           "release", "rolling", "beta", "alpha", "testing", "test", "snapshot", "unstable", "trunk", "lts", "latest-stable"})
_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^[a-z][a-z0-9]*(?:[+._-][a-z][a-z0-9]*)*:[0-9a-fA-F]{32,}$")


@dataclass(frozen=True)
class ImageRef:
    raw: str
    registry: str
    repo: str
    tag: str | None
    digest: str | None

    @property
    def canonical_repo(self) -> str:
        return f"{self.registry}/{self.repo}"


def _sanitize(s: Any, limit: int = 200) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(s))[:limit]


def parse_image(raw: Any) -> ImageRef | None:
    """Parse ``[registry/]repo[:tag][@digest]``. Returns None for anything that is not a valid reference."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or len(s) > MAX_IMAGE_LEN or s != raw or re.search(r"\s|[\x00-\x1f\x7f]", s):
        return None
    name, sep, dg = s.partition("@")
    digest: str | None = dg if sep else None
    if digest is not None and not _DIGEST.match(digest):
        return None
    tag = None
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = name.rsplit(":", 1)
        if not _TAG.match(tag):
            return None
    parts = name.split("/")
    first = parts[0]
    if len(parts) > 1 and ("." in first or ":" in first or first == "localhost"):
        registry, path = first.lower(), parts[1:]
        if not re.match(r"^[a-z0-9.-]+(:\d{1,5})?$", registry):
            return None
    else:
        registry, path = DOCKER_HUB, parts
    if registry in {"index.docker.io", "registry-1.docker.io"}:
        registry = DOCKER_HUB
    if not path or not all(_COMPONENT.match(p) for p in path):
        return None
    if registry == DOCKER_HUB and len(path) == 1:
        path = ["library"] + path
    return ImageRef(s, registry, "/".join(path), tag, digest)


@dataclass(frozen=True)
class ImagePolicy:
    allowed_registries: tuple[str, ...] = ()
    require_digest: bool = False

    def registry_allowed(self, ref: ImageRef) -> bool:
        if not self.allowed_registries:
            return True
        full = ref.canonical_repo
        for entry in self.allowed_registries:
            e = entry.strip().lower()
            if "/" in e:
                if fnmatch.fnmatchcase(full, e if not e.endswith("/") else e + "*"):
                    return True
            elif fnmatch.fnmatchcase(ref.registry, e):
                return True
        return False


def parse_image_policy(data: Any) -> ImagePolicy:
    if data is None:
        return ImagePolicy()
    if not isinstance(data, dict):
        raise ValueError("image policy must be a mapping")
    unknown = set(data) - {"allowed_registries", "require_digest"}
    if unknown:
        raise ValueError(f"image policy has unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    regs = data.get("allowed_registries") or []
    if not isinstance(regs, list) or len(regs) > 200 or not all(isinstance(r, str) and 0 < len(r.strip()) <= 253 and not re.search(r"\s", r.strip()) for r in regs):
        raise ValueError("allowed_registries must be a list of up to 200 registry names or patterns (no whitespace)")
    rd = data.get("require_digest", False)
    if not isinstance(rd, bool):
        raise ValueError("require_digest must be true or false")
    return ImagePolicy(tuple(r.strip() for r in regs), rd)


def load_image_policy(path: str | Path) -> ImagePolicy:
    p = Path(path)
    if p.stat().st_size > MAX_POLICY_BYTES:
        raise ValueError("image policy file is too large")
    try:
        return parse_image_policy(yaml.safe_load(p.read_text(encoding="utf-8")))
    except yaml.YAMLError as e:
        raise ValueError(f"invalid image policy: {e}") from e


def merge_policies(policy: ImagePolicy | None, extra_registries: list[str] | None) -> ImagePolicy:
    """Combine a policy file with ``--allow-registry`` values (validated like the file's own list)."""
    policy = policy or ImagePolicy()
    if not extra_registries:
        return policy
    extra = parse_image_policy({"allowed_registries": list(extra_registries)})
    return ImagePolicy(policy.allowed_registries + extra.allowed_registries, policy.require_digest)


def workload_images(resources: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    """(resource key, container name, raw image) for every container of every pod-bearing resource."""
    out = []
    for o in resources:
        if not isinstance(o, dict) or not o.get("kind"):
            continue
        try:
            pod, _ = _pod_spec(o)
        except Exception:  # malformed objects are reported by the schema checks
            continue
        if not isinstance(pod, dict):
            continue
        rk = resource_key(o)
        for key in ("initContainers", "containers", "ephemeralContainers"):
            for c in pod.get(key) or []:
                if isinstance(c, dict) and "image" in c:
                    out.append((rk, str(c.get("name", "container")), c.get("image")))
    return out


def image_findings(resources: list[dict[str, Any]], policy: ImagePolicy | None = None) -> list[Finding]:
    """KF-IMG-001..004. Pure string analysis: no registry or network access."""
    policy = policy or ImagePolicy()
    out: list[Finding] = []
    for rk, cname, raw in workload_images(resources):
        shown = _sanitize(raw) if isinstance(raw, str) else f"<{type(raw).__name__}>"
        ref = parse_image(raw)
        if ref is None:
            if raw in (None, ""):
                continue  # a missing image is already KF-SUP-001 / schema territory
            out.append(Finding("KF-IMG-004", "medium", "supply-chain", f"Malformed image reference: {cname}", rk,
                               f"image={shown!r} is not a valid [registry/]repository[:tag][@digest] reference",
                               "Use a valid, lower-case repository name with an explicit tag or digest."))
            continue
        if not ref.digest:
            out.append(Finding("KF-IMG-001", "medium" if policy.require_digest else "info", "supply-chain",
                               f"Image not pinned by digest: {cname}", rk, f"image={shown}",
                               "Pin the image with @sha256:<digest> so the bytes that were reviewed are the bytes that run."))
        if ref.tag and ref.tag.lower() in FLOATING_TAGS and not ref.digest:
            out.append(Finding("KF-IMG-002", "medium", "supply-chain", f"Mutable tag: {cname}", rk,
                               f"image={shown} uses the moving tag {ref.tag!r}",
                               "Use an immutable version tag, ideally with a digest."))
        if policy.allowed_registries and not policy.registry_allowed(ref):
            out.append(Finding("KF-IMG-003", "high", "supply-chain", f"Image from a registry outside the allow-list: {cname}", rk,
                               f"image={shown} registry={ref.registry}; allowed={', '.join(policy.allowed_registries)}",
                               "Mirror the image into an approved registry or extend the allow-list after review."))
    return out
