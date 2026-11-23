# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
from __future__ import annotations
import html,json
from dataclasses import replace
from pathlib import Path
from . import __version__
from .models import Assessment
from .registry import get_rule,SECURITY_SEVERITY,SEVERITY_RANK
_ORDER={'critical':0,'high':1,'medium':2,'low':3,'info':4}

def _md(v)->str:
 return str(v).replace('\\','\\\\').replace('|','\\|').replace('`',"'").replace('<','&lt;').replace('>','&gt;').replace('\r',' ').replace('\n',' ')

def _profile_line(p:dict)->str:
 return f"Profile: {p['name']} ({sum(p['dropped'].values())} finding(s) not counted, {len(p['adjusted'])} severity adjustment(s))"

def text_report(a:Assessment)->str:
 d=a.to_dict(); lines=[f"KubeFlight — {d['decision']}",f"Safety score: {d['score']}/100",f"Resources: {d['resources']}  Findings: {len(d['findings'])}",f"Estimated monthly workload cost: ${d['monthly_cost']:.2f}"]
 if d['cost_delta'] is not None:lines.append(f"Cost delta: ${d['cost_delta']:+.2f}")
 if d.get('profile'):lines.append(_profile_line(d['profile']))
 lines.append("")
 for f in sorted(d['findings'],key=lambda x:_ORDER.get(x['severity'],len(_ORDER))):
  lines.append(f"[{f['severity'].upper():8}] {f['category']:12} {f['resource']} — {f['title']}")
  lines.append(f"           ↳ {f['recommendation']}")
 if d['schedule']:
  lines += ["","Scheduling:"]
  for s in d['schedule']:lines.append(f"  {'✓' if s['schedulable'] else '✕'} {s['workload']}: {len(s['placements'])}/{s['replicas']} replicas placed on {', '.join(s['placements']) or 'none'}")
 if d['blast_radius']: lines += ["",f"Blast radius ({len(d['blast_radius'])}): "+", ".join(d['blast_radius'])]
 return "\n".join(lines)+"\n"

def json_report(a:Assessment)->str:return json.dumps(a.to_dict(),indent=2)+"\n"

def markdown_report(a:Assessment)->str:
 d=a.to_dict(); icon='✅' if d['decision']=='SAFE TO DEPLOY' else ('⚠️' if d['decision']=='REVIEW REQUIRED' else '⛔')
 lines=[f"## ✈️ KubeFlight — {icon} {d['decision']}","",f"**Safety score:** {d['score']}/100 · **Resources:** {d['resources']} · **Cost:** ${d['monthly_cost']:.2f}/mo"+(f" · **Profile:** {_md(d['profile']['name'])}" if d.get('profile') else ""),"", "| Severity | Category | Resource | Finding |","|---|---|---|---|"]
 for f in sorted(d['findings'],key=lambda x:_ORDER.get(x['severity'],len(_ORDER)))[:25]:lines.append(f"| {f['severity'].upper()} | {_md(f['category'])} | `{_md(f['resource'])}` | {_md(f['title'])} |")
 if d['blast_radius']:lines += ["",f"**Blast radius:** {len(d['blast_radius'])} dependent resource(s)."]
 lines += ["","_KubeFlight is a preflight simulator, not a substitute for Kubernetes admission controls or production validation._"]
 return "\n".join(lines)+"\n"

def _sarif_uri(path:str)->str:
 p=Path(path)
 try:p=p.resolve().relative_to(Path.cwd().resolve())
 except (ValueError,OSError):pass
 return p.as_posix()

def sarif_report(a:Assessment,states:list[str]|None=None)->str:
 d=a.to_dict(); rules={}; results=[]
 level={'critical':'error','high':'error','medium':'warning','low':'note','info':'note'}
 for n,f in enumerate(d['findings']):
  if f['id'] not in rules:
   reg=get_rule(f['id']); sev=reg.severity if reg else f['severity']
   help_text=f['recommendation'] if reg is None else f"{reg.rationale}\n\nFix: {reg.fix}"+(f"\n\nReference: {reg.reference}" if reg.reference else "")
   help_md=f['recommendation'] if reg is None else f"**Why it matters:** {reg.rationale}\n\n**Fix:** {reg.fix}"+(f"\n\n[Reference]({reg.reference})" if reg.reference else "")
   rule={"id":f['id'],"name":f['id'],"shortDescription":{"text":f['title']},"fullDescription":{"text":reg.rationale if reg else f['title']},
         "help":{"text":help_text,"markdown":help_md},
         "defaultConfiguration":{"level":level.get(sev,'warning')},
         "properties":{"security-severity":SECURITY_SEVERITY.get(sev,"5.0"),"tags":["kubernetes","kubeflight",f['category']]}}
   if reg and reg.reference:rule["helpUri"]=reg.reference
   rules[f['id']]=rule
  loc={"logicalLocations":[{"fullyQualifiedName":f['resource'],"kind":"resource"}]}
  where=a.locations.get(f['resource'])
  if where:loc["physicalLocation"]={"artifactLocation":{"uri":_sarif_uri(where[0])},"region":{"startLine":max(1,int(where[1]))}}
  results.append({"ruleId":f['id'],"ruleIndex":list(rules).index(f['id']),"level":level.get(f['severity'],'warning'),
                  "message":{"text":f"{f['resource']}: {f['title']}. {f['evidence']}"},"locations":[loc],
                  "properties":{"security-severity":SECURITY_SEVERITY.get(f['severity'],"5.0"),"severity":f['severity'],"category":f['category']}})
  if states and n<len(states):results[-1]["baselineState"]=states[n]
 sarif={"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"KubeFlight","version":__version__,"informationUri":"https://github.com/zyvorai/kubeflight","rules":list(rules.values())}},"results":results}]}
 return json.dumps(sarif,indent=2)+"\n"

def filter_min_severity(a:Assessment,min_severity:str|None)->Assessment:
 """Return a copy of the assessment whose findings (and summary) are limited to >= min_severity.
 Score and decision still reflect the full set of findings."""
 if not min_severity or min_severity=="info":return a
 floor=SEVERITY_RANK[min_severity]
 kept=[f for f in a.findings if SEVERITY_RANK.get(f.severity,0)>=floor]
 summary={k:(v if SEVERITY_RANK[k]>=floor else 0) for k,v in a.summary.items()}
 return replace(a,findings=kept,summary=summary)

def html_report(a:Assessment)->str:
 d=a.to_dict(); rows="".join(f"<tr><td><span class='sev {html.escape(f['severity'])}'>{html.escape(f['severity'])}</span></td><td>{html.escape(f['category'])}</td><td><code>{html.escape(f['resource'])}</code></td><td><b>{html.escape(f['title'])}</b><br><small>{html.escape(f['evidence'])}</small><br><em>{html.escape(f['recommendation'])}</em></td></tr>" for f in sorted(d['findings'],key=lambda x:_ORDER.get(x['severity'],len(_ORDER))))
 sched="".join(f"<li>{'✓' if s['schedulable'] else '✕'} <code>{html.escape(s['workload'])}</code> — {len(s['placements'])}/{s['replicas']} placed</li>" for s in d['schedule'])
 return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>KubeFlight report</title><style>*{{box-sizing:border-box}}body{{font:15px -apple-system,BlinkMacSystemFont,"SF Pro Text",Segoe UI,sans-serif;max-width:1180px;margin:0 auto;padding:64px 28px;color:#1d1d1f;background:#fbfbfd}}h1{{font-size:56px;letter-spacing:-.04em;margin:0}}.hero{{padding:52px 0}}.score{{font-size:96px;font-weight:700;letter-spacing:-.06em}}.card{{background:white;border-radius:24px;padding:28px;margin:20px 0;box-shadow:0 10px 40px #0000000a}}table{{width:100%;border-collapse:collapse}}td{{padding:14px;border-bottom:1px solid #eee;vertical-align:top}}small{{color:#6e6e73}}em{{color:#424245}}code{{background:#f5f5f7;padding:2px 5px;border-radius:6px}}.sev{{font-weight:700;text-transform:uppercase;font-size:11px}}@media(max-width:700px){{h1{{font-size:42px}}.score{{font-size:72px}}td:nth-child(2),td:nth-child(3){{display:none}}}}</style></head><body><div class="hero"><h1>KubeFlight</h1><div class="score">{d['score']}</div><h2>{html.escape(d['decision'])}</h2><p>{d['resources']} resources · ${d['monthly_cost']:.2f}/month normalized estimate · Kubernetes {html.escape(d['target_kubernetes'])}</p></div><div class="card"><h2>Scheduling</h2><ul>{sched or '<li>No cluster snapshot supplied</li>'}</ul></div><div class="card"><h2>Findings</h2><table>{rows or '<tr><td>No findings.</td></tr>'}</table></div></body></html>'''
