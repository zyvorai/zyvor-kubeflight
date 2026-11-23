# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
from __future__ import annotations
import argparse,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
from . import __version__
from .cluster import in_cluster_snapshot,load_snapshot,ClusterError
from .engine import assess
from .suppress import load_suppressions
from .parser import load_path,autodetect_path,ManifestError
from .report import text_report,json_report,html_report,markdown_report,sarif_report,filter_min_severity
from .registry import get_rule,format_rule,REGISTRY,SEVERITIES


def _server_dry_run(path:str)->tuple[bool,str]:
    if not shutil.which("kubectl"): return False,"kubectl is not installed"
    try:
        p=subprocess.run(["kubectl","apply","--dry-run=server","-f",path],text=True,capture_output=True,timeout=60)
        return p.returncode==0,(p.stdout+p.stderr).strip()
    except Exception as e:return False,str(e)

def _explain(a)->int:
    if a.list or not a.id:
        for r in sorted(REGISTRY.values(),key=lambda r:r.id):print(f"{r.id}  {r.severity:8} {r.title}")
        return 0 if a.list else 2
    r=get_rule(a.id)
    if r is None:
        import difflib
        near=difflib.get_close_matches(a.id.strip().upper(),list(REGISTRY),n=3)
        print(f"kubeflight: unknown finding id {a.id!r}"+(f"; did you mean {', '.join(near)}?" if near else "; try `kubeflight explain --list`"),file=sys.stderr);return 2
    print(json.dumps(r.to_dict(),indent=2) if a.json else format_rule(r),end="" if not a.json else "\n");return 0

def main(argv=None):
    p=argparse.ArgumentParser(prog="kubeflight",description="Kubernetes deployment preflight simulator — know what may break before you deploy.")
    p.add_argument("--version",action="version",version=f"kubeflight {__version__}")
    sub=p.add_subparsers(dest="cmd",required=True)
    for name,helptext in (("check","Analyze Kubernetes manifests"),("plan","Auto-detect and analyze this repository's Kubernetes deployment")):
        c=sub.add_parser(name,help=helptext)
        if name=="check":c.add_argument("path")
        else:c.add_argument("path",nargs="?",default=".")
        c.add_argument("--baseline");c.add_argument("--cluster-snapshot");c.add_argument("--in-cluster",action="store_true")
        c.add_argument("--format",choices=["text","json","html","markdown","sarif"],default="text");c.add_argument("--output");c.add_argument("--fail-on",choices=["never","low","medium","high","critical"],default="critical");c.add_argument("--min-severity",choices=list(SEVERITIES),default="info",help="Only show findings at or above this severity in the report (the --fail-on gate and score still use every finding)");c.add_argument("--ignore-file",help="YAML list of reviewed, expiring suppressions");c.add_argument("--server-dry-run",action="store_true")
    e=sub.add_parser("explain",help="Explain a finding id: why it matters and how to fix it");e.add_argument("id",nargs="?",help="Finding id such as KF-SEC-030");e.add_argument("--list",action="store_true",help="List every known finding id");e.add_argument("--json",action="store_true",help="Print as JSON")
    s=sub.add_parser("serve",help="Run the KubeFlight dashboard/API");s.add_argument("--host",default="0.0.0.0");s.add_argument("--port",type=int,default=8080)
    a=p.parse_args(argv)
    if a.cmd=="explain":return _explain(a)
    if a.cmd=="serve":
        import uvicorn;uvicorn.run("kubeflight.server:app",host=a.host,port=a.port,log_level="info");return 0
    try:
        path=autodetect_path(a.path) if a.cmd=="plan" else Path(a.path)
        resources=load_path(path);baseline=load_path(a.baseline) if a.baseline else None
        snapshot=load_snapshot(a.cluster_snapshot) if a.cluster_snapshot else (in_cluster_snapshot() if a.in_cluster else None)
        result=assess(resources,baseline,snapshot,suppressions=load_suppressions(a.ignore_file) if a.ignore_file else None)
        if a.server_dry_run:
            ok,msg=_server_dry_run(str(path))
            if not ok:
                print(f"kubeflight: server dry-run failed/unavailable: {msg}",file=sys.stderr)
                return 4
    except (ManifestError,ClusterError,ValueError,OSError,json.JSONDecodeError) as e:
        print(f"kubeflight: {e}",file=sys.stderr);return 2
    renderer={"text":text_report,"json":json_report,"html":html_report,"markdown":markdown_report,"sarif":sarif_report}[a.format]
    out=renderer(filter_min_severity(result,a.min_severity))
    if a.output:Path(a.output).write_text(out,encoding="utf-8")
    else:print(out,end="")
    sev={f.severity for f in result.findings}
    order=["low","medium","high","critical"]
    if a.fail_on!="never" and sev&set(order[order.index(a.fail_on):]):return 3
    return 0

if __name__=="__main__":raise SystemExit(main())
