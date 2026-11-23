# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
from __future__ import annotations
import asyncio,hmac,json,os,time
from collections import defaultdict,deque
from pathlib import Path
from typing import Any
from fastapi import FastAPI,HTTPException,Request
from fastapi.responses import HTMLResponse,JSONResponse
from pydantic import BaseModel,Field
from . import __version__
from .cluster import in_cluster_snapshot,ClusterError
from .engine import assess
from .parser import parse_text,ManifestError
from .suppress import parse_suppressions
from .plus import plus_findings
from .rules import parse_rules,MAX_FILE_BYTES as MAX_RULES_BYTES
from .engine import TARGET_KUBERNETES
from .apis import parse_version
from .registry import REGISTRY,get_rule
from .images import parse_image_policy,merge_policies
from .vulns import parse_sbom,parse_advisories
from .plus import supply_limitations
from .profiles import parse_profile,builtin_profile,builtin_names
from .helmvalues import values_findings
from .diffreport import normalize_report,diff_reports

WEB=Path(__file__).with_name("web")
app=FastAPI(title="KubeFlight",version=__version__,docs_url="/api/docs",redoc_url=None)
MAX_BODY=int(os.getenv("KUBEFLIGHT_MAX_BODY_BYTES","4194304"));MAX_CONCURRENT=int(os.getenv("KUBEFLIGHT_MAX_CONCURRENT","8"));RATE=int(os.getenv("KUBEFLIGHT_RATE_PER_MINUTE","60"));SEM=asyncio.Semaphore(MAX_CONCURRENT);HITS=defaultdict(deque)

PROBES={"/api/healthz","/api/readyz"}

def _auth_ok(request:Request)->bool:
    expected=os.getenv("KUBEFLIGHT_API_TOKEN","")
    if not expected:return True
    auth=request.headers.get("authorization","")
    got=auth[7:] if auth.lower().startswith("bearer ") else ""
    return hmac.compare_digest(got.encode(),expected.encode())

@app.middleware("http")
async def guard(request:Request,call_next):
    cl=request.headers.get("content-length")
    if cl:
        try:
            if int(cl)>MAX_BODY:return JSONResponse({"detail":"request body too large"},status_code=413)
        except ValueError:return JSONResponse({"detail":"invalid Content-Length"},status_code=400)
    if request.url.path in PROBES:return await call_next(request)
    ip=request.client.host if request.client else "unknown";now=time.time();q=HITS[ip]
    while q and q[0]<now-60:q.popleft()
    if len(HITS)>1024:
        for k in [k for k,v in HITS.items() if k!=ip and (not v or v[-1]<now-60)]:del HITS[k]
    if len(q)>=RATE:return JSONResponse({"detail":"rate limit exceeded"},status_code=429)
    q.append(now)
    async with SEM:return await call_next(request)

class CheckRequest(BaseModel):
    manifests:str=Field(min_length=1,max_length=MAX_BODY)
    baseline:str|None=Field(default=None,max_length=MAX_BODY)
    snapshot:dict[str,Any]|None=None
    use_in_cluster:bool=False
    rules:str|None=Field(default=None,max_length=MAX_RULES_BYTES)
    target_kubernetes:str=Field(default=TARGET_KUBERNETES,max_length=32)
    field_check:bool=True
    suppressions:list[dict[str,Any]]|None=Field(default=None,max_length=200)
    profile:str|None=Field(default=None,max_length=40)
    profile_spec:dict[str,Any]|None=None
    image_policy:dict[str,Any]|None=None
    allow_registries:list[str]=Field(default_factory=list,max_length=200)
    sboms:list[dict[str,Any]]=Field(default_factory=list,max_length=20)  # each: {"document": <CycloneDX/SPDX JSON>, "image": optional image to bind}
    advisories:list[dict[str,Any]]=Field(default_factory=list,max_length=10)  # each: a simple-format or OSV-subset document (with version/expires)
    baseline_report:dict[str,Any]|None=None

class ValuesRequest(BaseModel):
    values:str=Field(min_length=1,max_length=524288)
    name:str=Field(default="values.yaml",max_length=100)
    profile:str|None=Field(default=None,max_length=40)
    profile_spec:dict[str,Any]|None=None
    suppressions:list[dict[str,Any]]|None=Field(default=None,max_length=200)
    baseline_report:dict[str,Any]|None=None

class DiffRequest(BaseModel):
    old:dict[str,Any];new:dict[str,Any]

def _profile(name,spec):
    if spec is not None:return parse_profile(spec,"request profile",default_extends=name)
    return builtin_profile(name) if name else None

def _with_diff(out,baseline_report):
    if baseline_report is not None:
        diff=diff_reports(normalize_report(baseline_report,"baseline_report"),normalize_report(out,"current"))
        out["diff"]={k:v for k,v in diff.items() if k!="states"}
    return out

@app.get("/",response_class=HTMLResponse)
def home():return (WEB/"index.html").read_text(encoding="utf-8")
@app.get("/api/healthz")
def healthz():return {"status":"ok","version":__version__}
@app.get("/api/readyz")
def readyz():return {"status":"ready"}
@app.get("/api/demo")
def demo():return {"manifests":(WEB/"demo-app.yaml").read_text(),"baseline":(WEB/"demo-baseline.yaml").read_text(),"snapshot":json.loads((WEB/"demo-cluster-snapshot.json").read_text())}
@app.get("/api/rules")
def rules_list():return {"rules":[r.to_dict() for r in sorted(REGISTRY.values(),key=lambda r:r.id)]}
@app.get("/api/rules/{rule_id}")
def rule_one(rule_id:str):
    r=get_rule(rule_id[:40])
    if r is None:raise HTTPException(404,"unknown finding id")
    return r.to_dict()
@app.get("/api/profiles")
def profiles_list():return {"profiles":[builtin_profile(n).to_dict() for n in builtin_names()]}
@app.post("/api/diff")
def diff(req:DiffRequest):
    try:d=diff_reports(normalize_report(req.old,"old"),normalize_report(req.new,"new"))
    except ValueError as e:raise HTTPException(400,str(e)) from e
    return {k:v for k,v in d.items() if k!="states"}
@app.post("/api/values")
def values(req:ValuesRequest,request:Request):
    if not _auth_ok(request):raise HTTPException(401,"invalid bearer token")
    try:
        findings,locs=values_findings(req.values,req.name)
        sups=parse_suppressions({"ignore":req.suppressions}) if req.suppressions else None
        out=assess([],suppressions=sups,extra=findings,profile=_profile(req.profile,req.profile_spec)).to_dict()
        return _with_diff(out,req.baseline_report)
    except (ValueError,TypeError) as e:raise HTTPException(400,str(e)) from e
@app.post("/api/check")
def check(req:CheckRequest,request:Request):
    if not _auth_ok(request):raise HTTPException(401,"invalid bearer token")
    try:
        resources=parse_text(req.manifests);baseline=parse_text(req.baseline) if req.baseline else None;snapshot=req.snapshot
        if req.use_in_cluster:
            if os.getenv("KUBEFLIGHT_LIVE_CLUSTER","false").lower() not in {"1","true","yes"}:raise HTTPException(403,"live-cluster access is disabled; set KUBEFLIGHT_LIVE_CLUSTER=true explicitly")
            if not os.getenv("KUBEFLIGHT_API_TOKEN"):raise HTTPException(403,"live-cluster access requires KUBEFLIGHT_API_TOKEN")
            snapshot=in_cluster_snapshot()
        sups=parse_suppressions({"ignore":req.suppressions}) if req.suppressions else None
        parse_version(req.target_kubernetes)
        sboms=[parse_sbom(x.get("document"),"request sbom",x.get("image")) for x in req.sboms];dbs=[parse_advisories(x,"request advisories") for x in req.advisories]
        policy=merge_policies(parse_image_policy(req.image_policy),req.allow_registries)
        extra=plus_findings(resources,target=req.target_kubernetes,rules=parse_rules(req.rules,'request rules') if req.rules else None,field_check=req.field_check,image_policy=policy,sboms=sboms,advisories=dbs)
        result=assess(resources,baseline,snapshot,target_kubernetes=req.target_kubernetes,suppressions=sups,extra=extra,profile=_profile(req.profile,req.profile_spec))
        result.limitations.extend(supply_limitations(sboms,dbs))
        return _with_diff(result.to_dict(),req.baseline_report)
    except HTTPException:raise
    except (ManifestError,ClusterError,ValueError,TypeError) as e:raise HTTPException(400,str(e)) from e
