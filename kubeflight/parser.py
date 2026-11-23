# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import shutil, subprocess, tempfile
import yaml

SUPPORTED_EXTENSIONS={".yaml",".yml",".json"}
class ManifestError(ValueError): pass

class Manifest(dict):
    """A parsed object that remembers where it came from (``source_file``/``source_line``).

    It compares and serializes like a plain dict, so hashing and baseline diffs are unaffected."""
    source_file: str | None = None
    source_line: int | None = None

def _located(obj:dict[str,Any], source:str|None, line:int|None)->dict[str,Any]:
    m=Manifest(obj); m.source_file=source; m.source_line=line; return m

def _flatten(doc:Any, source:str|None=None, node:Any=None)->Iterable[dict[str,Any]]:
    if doc is None:return
    if not isinstance(doc,dict): raise ManifestError("Each YAML document must be a Kubernetes object")
    line=node.start_mark.line+1 if node is not None else None
    if doc.get("kind")=="List" and isinstance(doc.get("items"),list):
        item_nodes=[]
        if node is not None and isinstance(getattr(node,"value",None),list):
            for k,v in node.value:
                if getattr(k,"value",None)=="items" and isinstance(getattr(v,"value",None),list): item_nodes=v.value
        for i,item in enumerate(doc["items"]):
            if isinstance(item,dict):
                n=item_nodes[i] if i<len(item_nodes) else None
                yield _located(item,source,n.start_mark.line+1 if n is not None else line)
        return
    yield _located(doc,source,line)

def parse_text(text:str,source:str="input",locate:bool=True)->list[dict[str,Any]]:
    """Parse YAML/JSON text. With ``locate`` the objects carry ``source_file``/``source_line``
    (skipped for the anonymous ``input`` source and for rendered Helm/Kustomize output)."""
    src=source if locate and source!="input" else None
    try:
        out=[]
        loader=yaml.SafeLoader(text)
        try:
            while loader.check_node():
                node=loader.get_node()
                out.extend(_flatten(loader.construct_document(node),src,node) or [])
        finally:
            loader.dispose()
        return out
    except yaml.YAMLError as exc: raise ManifestError(f"Invalid YAML in {source}: {exc}") from exc

def _run(args:list[str],cwd:Path)->str:
    try:return subprocess.check_output(args,cwd=cwd,text=True,stderr=subprocess.STDOUT,timeout=45)
    except FileNotFoundError as exc: raise ManifestError(f"Required renderer not installed: {args[0]}") from exc
    except subprocess.CalledProcessError as exc: raise ManifestError(f"Renderer failed: {' '.join(args)}\n{exc.output}") from exc
    except subprocess.TimeoutExpired as exc: raise ManifestError(f"Renderer timed out: {' '.join(args)}") from exc

def load_path(path:str|Path,*,render:bool=True)->list[dict[str,Any]]:
    p=Path(path)
    if not p.exists(): raise ManifestError(f"Path does not exist: {p}")
    if p.is_dir() and render:
        if (p/"Chart.yaml").exists(): return parse_text(_run(["helm","template","kubeflight-input","."],p),str(p),locate=False)
        if (p/"kustomization.yaml").exists() or (p/"kustomization.yml").exists():
            if shutil.which("kubectl"): text=_run(["kubectl","kustomize","."],p)
            else: text=_run(["kustomize","build","."],p)
            return parse_text(text,str(p),locate=False)
    files=[p] if p.is_file() else sorted(x for x in p.rglob("*") if x.suffix.lower() in SUPPORTED_EXTENSIONS and ".github" not in x.parts and "node_modules" not in x.parts and ".venv" not in x.parts)
    if not files: raise ManifestError(f"No YAML/JSON manifests found under {p}")
    out=[]
    for f in files: out.extend(parse_text(f.read_text(encoding="utf-8"),str(f)))
    return out

def autodetect_path(root:str|Path=".")->Path:
    root=Path(root)
    for rel in ("deploy/kubernetes","k8s","kubernetes","manifests","deploy","charts"):
        p=root/rel
        if p.exists():
            if p.name=="charts":
                charts=[x for x in p.iterdir() if x.is_dir() and (x/"Chart.yaml").exists()]
                if len(charts)==1:return charts[0]
            else:return p
    if (root/"Chart.yaml").exists() or (root/"kustomization.yaml").exists():return root
    return root

def resource_key(obj:dict[str,Any])->str:
    m=obj.get("metadata") or {}; return f"{obj.get('kind','Unknown')}/{m.get('namespace','default')}/{m.get('name','unnamed')}"
