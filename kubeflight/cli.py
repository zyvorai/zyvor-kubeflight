# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
from __future__ import annotations
import argparse,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
from . import __version__
from .cluster import in_cluster_snapshot,load_snapshot,ClusterError
from .engine import assess,TARGET_KUBERNETES
from .plus import plus_findings
from .apis import parse_version
from .rules import load_rules,run_rule_tests,RuleError
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
        c.add_argument("--rules",action="append",default=[],help="YAML custom rules file (KF-CUS-xxx); repeatable")
        c.add_argument("--target-kubernetes",default=TARGET_KUBERNETES,help="Kubernetes minor version to check API removals against (default %(default)s)")
        c.add_argument("--no-field-check",action="store_true",help="skip offline field/type validation (KF-FLD-xxx)")
    r=sub.add_parser("rules",help="Work with custom rule files");rsub=r.add_subparsers(dest="rules_cmd",required=True)
    rt=rsub.add_parser("test",help="Run the tests embedded in custom rule files");rt.add_argument("files",nargs="+");rt.add_argument("--require-tests",action="store_true",help="fail rules that have no tests")
    e=sub.add_parser("explain",help="Explain a finding id: why it matters and how to fix it");e.add_argument("id",nargs="?",help="Finding id such as KF-SEC-030");e.add_argument("--list",action="store_true",help="List every known finding id");e.add_argument("--json",action="store_true",help="Print as JSON")
    s=sub.add_parser("serve",help="Run the KubeFlight dashboard/API");s.add_argument("--host",default="0.0.0.0");s.add_argument("--port",type=int,default=8080)
    a=p.parse_args(argv)
    if a.cmd=="explain":return _explain(a)
    if a.cmd=="serve":
        import uvicorn;uvicorn.run("kubeflight.server:app",host=a.host,port=a.port,log_level="info");return 0
    if a.cmd=="rules":
        try:rules=load_rules(a.files)
        except RuleError as e:
            print(f"kubeflight: {e}",file=sys.stderr);return 2
        results=run_rule_tests(rules,a.require_tests);bad=0
        for r in results:
            print(f"{'PASS' if r['ok'] else 'FAIL'} {r['rule']} {r['test']}"+("" if r["ok"] else f" -- {r['detail']}"));bad+=not r["ok"]
        print(f"{len(rules)} rule(s), {len(results)} test(s), {bad} failed")
        return 3 if bad else 0
    try:
        path=autodetect_path(a.path) if a.cmd=="plan" else Path(a.path)
        resources=load_path(path);baseline=load_path(a.baseline) if a.baseline else None
        snapshot=load_snapshot(a.cluster_snapshot) if a.cluster_snapshot else (in_cluster_snapshot() if a.in_cluster else None)
        parse_version(a.target_kubernetes)
        extra=plus_findings(resources,target=a.target_kubernetes,rules=load_rules(a.rules) if a.rules else None,field_check=not a.no_field_check)
        result=assess(resources,baseline,snapshot,target_kubernetes=a.target_kubernetes,suppressions=load_suppressions(a.ignore_file) if a.ignore_file else None,extra=extra)
        if a.server_dry_run:
            ok,msg=_server_dry_run(str(path))
            if not ok:
                print(f"kubeflight: server dry-run failed/unavailable: {msg}",file=sys.stderr)
                return 4
    except (ManifestError,ClusterError,RuleError,ValueError,OSError,json.JSONDecodeError) as e:
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
