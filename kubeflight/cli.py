# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
from __future__ import annotations
import argparse,json,os,shutil,subprocess,sys,tempfile
from dataclasses import replace
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
from .images import load_image_policy,merge_policies
from .vulns import load_sbom,load_advisories
from .plus import supply_limitations
from .profiles import load_profile,builtin_names,builtin_profile
from .helmvalues import load_values
from .diffreport import load_report,normalize_report,diff_reports,new_findings_at_or_above,diff_markdown,pr_comment_report,text_diff,COMMENT_MARKER


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

def _add_output_args(c):
    c.add_argument("--format",choices=["text","json","html","markdown","sarif","pr-comment"],default="text",help="pr-comment: markdown for a PR comment or GITHUB_STEP_SUMMARY (hidden marker, collapsed details, size-capped)")
    c.add_argument("--output");c.add_argument("--fail-on",choices=["never","low","medium","high","critical"],default=None,help="exit 3 at or above this severity (default: the profile's fail_on, else critical)")
    c.add_argument("--min-severity",choices=list(SEVERITIES),default="info",help="Only show findings at or above this severity in the report (the --fail-on gate and score still use every finding)")
    c.add_argument("--ignore-file",help="YAML list of reviewed, expiring suppressions")
    c.add_argument("--profile",choices=builtin_names(),help="policy profile preset: which findings count and at what severity (see docs/PROFILES.md)")
    c.add_argument("--profile-file",help="YAML profile (layered on --profile when both are given)")
    c.add_argument("--baseline-report",help="earlier JSON report; shows only findings introduced since it (JSON adds a 'diff' key, SARIF sets baselineState)")
    c.add_argument("--fail-on-new",nargs="?",const="low",choices=["info","low","medium","high","critical"],help="exit 3 only for findings that are new vs --baseline-report at or above this severity (default low); replaces --fail-on")

def _diffs(a,result):
    """(diff for the displayed findings, diff for every finding) against --baseline-report, or (None,None)."""
    if not a.baseline_report:
        if a.fail_on_new:raise ValueError("--fail-on-new needs --baseline-report")
        return None,None
    old=load_report(a.baseline_report)
    return diff_reports(old,normalize_report(filter_min_severity(result,a.min_severity).to_dict(),"current")),diff_reports(old,normalize_report(result.to_dict(),"current"))

def _render(a,result,shown_diff):
    shown=filter_min_severity(result,a.min_severity)
    if a.format=="pr-comment":return pr_comment_report(shown,shown_diff)
    if a.format=="sarif":return sarif_report(shown,shown_diff["states"] if shown_diff else None)
    if a.format=="json" and shown_diff:
        d=shown.to_dict();d["diff"]={k:v for k,v in shown_diff.items() if k!="states"};return json.dumps(d,indent=2)+"\n"
    renderer={"text":text_report,"json":json_report,"html":html_report,"markdown":markdown_report}[a.format]
    out=renderer(shown)
    if shown_diff and a.format=="markdown":out+="\n"+diff_markdown(shown_diff)
    if shown_diff and a.format=="text":out+="\nChange vs baseline report:\n"+text_diff(shown_diff)
    return out

def _gate(a,result,full_diff,profile)->int:
    if a.fail_on_new:
        return 3 if new_findings_at_or_above(full_diff,a.fail_on_new) else 0
    fail_on=a.fail_on or (profile.fail_on if profile else None) or "critical"
    order=["low","medium","high","critical"]
    sev={f.severity for f in result.findings}
    return 3 if fail_on!="never" and sev&set(order[order.index(fail_on):]) else 0

def _finish(a,result,profile)->int:
    shown_diff,full_diff=_diffs(a,result)
    out=_render(a,result,shown_diff)
    if a.output:Path(a.output).write_text(out,encoding="utf-8")
    else:print(out,end="")
    return _gate(a,result,full_diff,profile)

def _diff_report_cmd(a)->int:
    try:
        diff=diff_reports(load_report(a.old),load_report(a.new))
        public={k:v for k,v in diff.items() if k!="states"}
        out={"json":json.dumps(public,indent=2)+"\n","markdown":COMMENT_MARKER+"\n## ✈️ KubeFlight\n\n"+diff_markdown(diff),"text":text_diff(diff)}[a.format]
    except (ValueError,OSError) as e:
        print(f"kubeflight: {e}",file=sys.stderr);return 2
    if a.output:Path(a.output).write_text(out,encoding="utf-8")
    else:print(out,end="")
    return 3 if a.fail_on_new and new_findings_at_or_above(diff,a.fail_on_new) else 0

def _profiles_cmd(a)->int:
    try:
        if a.profiles_cmd=="list":
            for n in builtin_names():
                p=builtin_profile(n);print(f"{n:11} fail_on={p.fail_on or 'critical':8} min_severity={p.min_severity:8} {p.description}")
            return 0
        print(json.dumps(builtin_profile(a.name).to_dict(),indent=2));return 0
    except ValueError as e:
        print(f"kubeflight: {e}",file=sys.stderr);return 2

def main(argv=None):
    p=argparse.ArgumentParser(prog="kubeflight",description="Kubernetes deployment preflight simulator — know what may break before you deploy.")
    p.add_argument("--version",action="version",version=f"kubeflight {__version__}")
    sub=p.add_subparsers(dest="cmd",required=True)
    for name,helptext in (("check","Analyze Kubernetes manifests"),("plan","Auto-detect and analyze this repository's Kubernetes deployment")):
        c=sub.add_parser(name,help=helptext)
        if name=="check":c.add_argument("path")
        else:c.add_argument("path",nargs="?",default=".")
        c.add_argument("--baseline");c.add_argument("--cluster-snapshot");c.add_argument("--in-cluster",action="store_true")
        _add_output_args(c);c.add_argument("--server-dry-run",action="store_true")
        c.add_argument("--rules",action="append",default=[],help="YAML custom rules file (KF-CUS-xxx); repeatable")
        c.add_argument("--target-kubernetes",default=TARGET_KUBERNETES,help="Kubernetes minor version to check API removals against (default %(default)s)")
        c.add_argument("--no-field-check",action="store_true",help="skip offline field/type validation (KF-FLD-xxx)")
        c.add_argument("--image-policy",help="YAML image policy: allowed_registries, require_digest")
        c.add_argument("--allow-registry",action="append",default=[],help="registry (or registry/path/* pattern) images may come from; repeatable")
        c.add_argument("--sbom",action="append",default=[],metavar="FILE[=IMAGE]",help="CycloneDX or SPDX 2.x JSON SBOM, optionally bound to an image; repeatable; needs --advisories")
        c.add_argument("--advisories",action="append",default=[],metavar="FILE",help="advisory file (simple format or OSV subset) with version/expires; repeatable; needs --sbom")
    v=sub.add_parser("values",help="Hygiene checks on a raw Helm values.yaml (charts are not rendered)");v.add_argument("paths",nargs="+",help="values file(s) or chart directories");_add_output_args(v)
    d=sub.add_parser("diff-report",help="Show only findings introduced between two JSON reports");d.add_argument("old");d.add_argument("new")
    d.add_argument("--format",choices=["text","json","markdown"],default="text");d.add_argument("--output");d.add_argument("--fail-on-new",nargs="?",const="low",choices=["info","low","medium","high","critical"],help="exit 3 when new findings at or above this severity exist (default low)")
    pr=sub.add_parser("profiles",help="List or show built-in policy profiles");prs=pr.add_subparsers(dest="profiles_cmd",required=True);prs.add_parser("list");ps=prs.add_parser("show");ps.add_argument("name")
    r=sub.add_parser("rules",help="Work with custom rule files");rsub=r.add_subparsers(dest="rules_cmd",required=True)
    rt=rsub.add_parser("test",help="Run the tests embedded in custom rule files");rt.add_argument("files",nargs="+");rt.add_argument("--require-tests",action="store_true",help="fail rules that have no tests")
    e=sub.add_parser("explain",help="Explain a finding id: why it matters and how to fix it");e.add_argument("id",nargs="?",help="Finding id such as KF-SEC-030");e.add_argument("--list",action="store_true",help="List every known finding id");e.add_argument("--json",action="store_true",help="Print as JSON")
    s=sub.add_parser("serve",help="Run the KubeFlight dashboard/API");s.add_argument("--host",default="0.0.0.0");s.add_argument("--port",type=int,default=8080)
    a=p.parse_args(argv)
    if a.cmd=="explain":return _explain(a)
    if a.cmd=="diff-report":return _diff_report_cmd(a)
    if a.cmd=="profiles":return _profiles_cmd(a)
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
        profile=load_profile(a.profile,a.profile_file)
        sups=load_suppressions(a.ignore_file) if a.ignore_file else None
        if a.cmd=="values":
            findings,locs,_=load_values(a.paths)
            result=assess([],suppressions=sups,extra=findings,profile=profile);result.locations.update(locs)
            return _finish(a,result,profile)
        path=autodetect_path(a.path) if a.cmd=="plan" else Path(a.path)
        resources=load_path(path);baseline=load_path(a.baseline) if a.baseline else None
        snapshot=load_snapshot(a.cluster_snapshot) if a.cluster_snapshot else (in_cluster_snapshot() if a.in_cluster else None)
        parse_version(a.target_kubernetes)
        sboms=[load_sbom(x) for x in a.sbom];dbs=[load_advisories(x) for x in a.advisories]
        policy=merge_policies(load_image_policy(a.image_policy) if a.image_policy else None,a.allow_registry)
        extra=plus_findings(resources,target=a.target_kubernetes,rules=load_rules(a.rules) if a.rules else None,field_check=not a.no_field_check,image_policy=policy,sboms=sboms,advisories=dbs)
        result=assess(resources,baseline,snapshot,target_kubernetes=a.target_kubernetes,suppressions=sups,extra=extra,profile=profile)
        result.limitations.extend(supply_limitations(sboms,dbs))
        if a.server_dry_run:
            ok,msg=_server_dry_run(str(path))
            if not ok:
                print(f"kubeflight: server dry-run failed/unavailable: {msg}",file=sys.stderr)
                return 4
        return _finish(a,result,profile)
    except (ManifestError,ClusterError,RuleError,ValueError,OSError,json.JSONDecodeError) as e:
        print(f"kubeflight: {e}",file=sys.stderr);return 2

if __name__=="__main__":raise SystemExit(main())
