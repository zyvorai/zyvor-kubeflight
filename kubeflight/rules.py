# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
"""User-defined policy rules in YAML with a small, safe expression language.

There is no ``eval``/``exec``: expressions are tokenized and parsed by a
hand-written parser into a tuple AST and run by a bounded interpreter.

Rule file::

    rules:
      - id: KF-CUS-001            # KF-CUS-NNN (001-899 or 1000+)
        title: Containers must set a memory limit
        severity: high            # low|medium|high|critical
        kinds: [Deployment, StatefulSet, Pod]   # optional, default any
        match: 'pod != null'      # optional applicability filter
        assert: 'all c in containers: exists(c.resources.limits.memory)'
        message: optional evidence text
        recommendation: optional text
        tests:                    # used by `kubeflight rules test`
          - {name: ok, expect: pass, resource: {...}}

A finding is raised for every applicable resource where ``assert`` is false.

Expression language
  literals    1  1.5  'str'  "str"  true  false  null  [1, 2]
  paths       spec.replicas   metadata.labels["app.kubernetes.io/name"]
              spec.template.spec.containers[0].image   containers[*].image
              (missing -> null; a path with [*] yields a list of matches)
  roots       any top-level manifest field, plus ``pod`` (the pod spec of a
              workload) and ``containers`` (containers + initContainers)
  operators   == != < <= > >=  in  not in  and  or  not  ( )
  quantifiers all c in LIST: EXPR      any c in LIST: EXPR
  functions   len exists lower upper startswith endswith contains regex glob
              cpu mem keys default
Ordering compares only numbers with numbers and strings with strings
(otherwise false). Use ``cpu(x)`` (millicores) / ``mem(x)`` (bytes) to compare
Kubernetes quantities.

Safety limits (all enforced, all surfaced as errors, never hangs or crashes)
  rules file 256 KiB / 200 rules; expression 500 chars / 300 tokens / nesting 24;
  50,000 interpreter steps per rule+resource; regex patterns restricted to a
  backtracking-safe subset (no groups with quantifiers, no backreferences, no
  lookaround, at most 3 quantifiers) on subjects of at most 256 characters.
"""
from __future__ import annotations
import fnmatch
import functools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml
from .models import Finding
from .parser import resource_key
from .quantities import QuantityError, cpu_millicores, memory_bytes

MAX_FILE_BYTES = 256 * 1024
MAX_RULES = 200
MAX_TESTS_PER_RULE = 20
MAX_EXPR_CHARS = 500
MAX_TOKENS = 300
MAX_DEPTH = 24
MAX_STEPS = 50_000
MAX_LITERAL_ITEMS = 100
MAX_STRING_LITERAL = 200
MAX_REGEX_PATTERN = 100
MAX_REGEX_QUANTIFIERS = 3
MAX_REGEX_SUBJECT = 256
SEVERITIES = ("low", "medium", "high", "critical")
ID_RE = re.compile(r"^KF-CUS-(\d{3,4})$")
RULE_KEYS = {"id", "title", "severity", "category", "kinds", "match", "assert", "message", "recommendation", "tests"}
TEST_KEYS = {"name", "expect", "resource"}

class RuleError(ValueError):
    """Invalid rule file/expression, or a runtime evaluation failure."""

# ------------------------------------------------------------------ tokenizer

_TOKEN = re.compile(r"""\s*(?:(?P<num>\d+(?:\.\d+)?)|(?P<str>'[^'\\\n]*'|"[^"\\\n]*")|(?P<id>[A-Za-z_][A-Za-z0-9_]*)|(?P<op>==|!=|<=|>=|<|>|\(|\)|\[|\]|,|\.|:|\*|-))""")
_KEYWORDS = {"and", "or", "not", "in", "true", "false", "null", "all", "any"}

def _tokenize(src: str) -> list[tuple[str, Any]]:
    if not isinstance(src, str):
        raise RuleError("expression must be a string")
    if len(src) > MAX_EXPR_CHARS:
        raise RuleError(f"expression longer than {MAX_EXPR_CHARS} characters")
    toks: list[tuple[str, Any]] = []
    pos = 0
    n = len(src)
    while pos < n:
        if src[pos:].strip() == "":
            break
        m = _TOKEN.match(src, pos)
        if not m:
            raise RuleError(f"unexpected character {src[pos:].lstrip()[:1]!r} in expression")
        pos = m.end()
        if m.group("num") is not None:
            t = m.group("num"); toks.append(("lit", float(t) if "." in t else int(t)))
        elif m.group("str") is not None:
            s = m.group("str")[1:-1]
            if len(s) > MAX_STRING_LITERAL:
                raise RuleError(f"string literal longer than {MAX_STRING_LITERAL} characters")
            toks.append(("lit", s))
        elif m.group("id") is not None:
            w = m.group("id")
            if w in ("true", "false"): toks.append(("lit", w == "true"))
            elif w == "null": toks.append(("lit", None))
            elif w in _KEYWORDS: toks.append(("kw", w))
            else: toks.append(("id", w))
        else:
            toks.append(("op", m.group("op")))
        if len(toks) > MAX_TOKENS:
            raise RuleError(f"expression has more than {MAX_TOKENS} tokens")
    if not toks:
        raise RuleError("expression is empty")
    return toks

# ------------------------------------------------------------------- parser
# AST nodes (tuples): ("lit",v) ("list",[n]) ("path",root,[seg]) seg=("key",k)|("idx",i)|("star",)
# ("call",name,[n]) ("cmp",op,l,r) ("and",l,r) ("or",l,r) ("not",n) ("quant",kind,var,iter,body)

FUNCS = {"len": 1, "exists": 1, "lower": 1, "upper": 1, "startswith": 2, "endswith": 2, "contains": 2,
         "regex": 2, "glob": 2, "cpu": 1, "mem": 1, "keys": 1, "default": 2}

class _Parser:
    def __init__(self, toks):
        self.t = toks; self.i = 0; self.depth = 0
    def peek(self): return self.t[self.i] if self.i < len(self.t) else ("eof", None)
    def take(self):
        tok = self.peek(); self.i += 1; return tok
    def is_(self, kind, val=None):
        k, v = self.peek(); return k == kind and (val is None or v == val)
    def expect(self, kind, val=None):
        if not self.is_(kind, val):
            raise RuleError(f"expected {val or kind} but found {self.peek()[1]!r}" if self.peek()[0] != "eof" else f"expected {val or kind} but expression ended")
        return self.take()
    def enter(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise RuleError(f"expression nesting deeper than {MAX_DEPTH}")
    def leave(self): self.depth -= 1

    def parse(self):
        node = self.expr()
        if self.peek()[0] != "eof":
            raise RuleError(f"unexpected {self.peek()[1]!r} after end of expression")
        return node
    def expr(self):
        self.enter(); n = self.and_()
        while self.is_("kw", "or"):
            self.take(); n = ("or", n, self.and_())
        self.leave(); return n
    def and_(self):
        n = self.not_()
        while self.is_("kw", "and"):
            self.take(); n = ("and", n, self.not_())
        return n
    def not_(self):
        if self.is_("kw", "not"):
            self.take(); self.enter(); n = ("not", self.not_()); self.leave(); return n
        return self.cmp()
    def cmp(self):
        l = self.atom()
        k, v = self.peek()
        if k == "op" and v in ("==", "!=", "<", "<=", ">", ">="):
            self.take(); return ("cmp", v, l, self.atom())
        if k == "kw" and v == "in":
            self.take(); return ("cmp", "in", l, self.atom())
        if k == "kw" and v == "not" and self.i + 1 < len(self.t) and self.t[self.i + 1] == ("kw", "in"):
            self.take(); self.take(); return ("cmp", "not in", l, self.atom())
        return l
    def atom(self):
        k, v = self.peek()
        if k == "lit":
            self.take(); return ("lit", v)
        if k == "op" and v == "(":
            self.take(); n = self.expr(); self.expect("op", ")"); return n
        if k == "op" and v == "[":
            self.take(); self.enter(); items = []
            if not self.is_("op", "]"):
                while True:
                    items.append(self.expr())
                    if len(items) > MAX_LITERAL_ITEMS: raise RuleError("list literal too large")
                    if self.is_("op", ","): self.take(); continue
                    break
            self.expect("op", "]"); self.leave(); return ("list", items)
        if k == "kw" and v in ("all", "any"):
            self.take(); var = self.expect("id")[1]; self.expect("kw", "in"); self.enter()
            it = self.atom(); self.expect("op", ":"); body = self.expr(); self.leave()
            return ("quant", v, var, it, body)
        if k == "id":
            self.take()
            if self.is_("op", "("):
                if v not in FUNCS: raise RuleError(f"unknown function {v!r}")
                self.take(); self.enter(); args = []
                if not self.is_("op", ")"):
                    while True:
                        args.append(self.expr())
                        if self.is_("op", ","): self.take(); continue
                        break
                self.expect("op", ")"); self.leave()
                if len(args) != FUNCS[v]: raise RuleError(f"{v}() takes {FUNCS[v]} argument(s), got {len(args)}")
                return ("call", v, args)
            segs = []
            while True:
                if self.is_("op", "."):
                    self.take(); segs.append(("key", self.expect("id")[1]))
                elif self.is_("op", "["):
                    self.take()
                    if self.is_("op", "*"): self.take(); segs.append(("star",))
                    elif self.is_("lit") and isinstance(self.peek()[1], str): segs.append(("key", self.take()[1]))
                    elif self.is_("op", "-") and self.i + 1 < len(self.t) and self.t[self.i + 1][0] == "lit" and isinstance(self.t[self.i + 1][1], int) and not isinstance(self.t[self.i + 1][1], bool):
                        self.take(); segs.append(("idx", -self.take()[1]))
                    elif self.is_("lit") and isinstance(self.peek()[1], int) and not isinstance(self.peek()[1], bool): segs.append(("idx", self.take()[1]))
                    else: raise RuleError("index must be *, an integer or a quoted key")
                    self.expect("op", "]")
                else: break
            return ("path", v, segs)
        raise RuleError(f"unexpected {v!r}" if k != "eof" else "expression ended unexpectedly")

@functools.lru_cache(maxsize=512)
def compile_expr(src: str):
    return _Parser(_tokenize(src)).parse()

# ------------------------------------------------------------- regex safety

def check_regex(pat: Any) -> None:
    """Reject patterns outside a backtracking-safe subset; raise RuleError."""
    if not isinstance(pat, str):
        raise RuleError("regex pattern must be a string")
    if len(pat) > MAX_REGEX_PATTERN:
        raise RuleError(f"regex pattern longer than {MAX_REGEX_PATTERN} characters")
    quants = 0; i = 0; n = len(pat); prev_group_close = False
    while i < n:
        c = pat[i]
        if c == "\\":
            if i + 1 < n and pat[i + 1] in "123456789":
                raise RuleError("regex backreferences are not allowed")
            if i + 1 < n and pat[i + 1] in "kgN":
                raise RuleError("regex named/conditional references are not allowed")
            i += 2; prev_group_close = False; continue
        if c == "[":
            j = i + 1
            if j < n and pat[j] == "^": j += 1
            if j < n and pat[j] == "]": j += 1
            while j < n and pat[j] != "]":
                j += 2 if pat[j] == "\\" else 1
            i = j + 1; prev_group_close = False; continue
        if c == "(":
            if pat[i + 1:i + 2] == "?": raise RuleError("regex lookaround/flags/special groups '(?' are not allowed")
            i += 1; prev_group_close = False; continue
        if c == ")":
            i += 1; prev_group_close = True; continue
        q = 0
        if c in "*+?": q = 1
        elif c == "{":
            m = re.match(r"\{(\d+)(?:,(\d*))?\}", pat[i:])
            if m:
                if int(m.group(1)) > 100 or (m.group(2) and int(m.group(2)) > 100):
                    raise RuleError("regex repetition bound over 100")
                q = len(m.group(0))
        if q:
            if prev_group_close: raise RuleError("regex quantifier on a group is not allowed")
            quants += 1
            if quants > MAX_REGEX_QUANTIFIERS: raise RuleError(f"regex uses more than {MAX_REGEX_QUANTIFIERS} quantifiers")
            i += q if c == "{" else 1
            if i < n and pat[i] in "?+": i += 1
            prev_group_close = False; continue
        i += 1; prev_group_close = False

@functools.lru_cache(maxsize=256)
def _compiled(pat: str):
    check_regex(pat)
    try: return re.compile(pat)
    except re.error as e: raise RuleError(f"invalid regex: {e}") from e

# -------------------------------------------------------------- interpreter

class _Ctx:
    __slots__ = ("res", "steps", "roots")
    def __init__(self, res):
        from .engine import _pod_spec
        self.res = res; self.steps = 0
        pod, _ = _pod_spec(res)
        conts = []
        if isinstance(pod, dict):
            for key in ("containers", "initContainers"):
                v = pod.get(key)
                if isinstance(v, list): conts += [c for c in v if isinstance(c, dict)]
        self.roots = {"pod": pod, "containers": conts if pod is not None else []}
    def tick(self, n=1):
        self.steps += n
        if self.steps > MAX_STEPS:
            raise RuleError(f"evaluation exceeded {MAX_STEPS} steps")

def _eq(a, b):
    if isinstance(a, bool) or isinstance(b, bool): return isinstance(a, bool) and isinstance(b, bool) and a == b
    return a == b

def _num(x): return isinstance(x, (int, float)) and not isinstance(x, bool)

def _truthy(v, what):
    if not isinstance(v, bool): raise RuleError(f"{what} needs a boolean but got {_tn(v)}")
    return v

def _tn(v): return "null" if v is None else type(v).__name__

def _walk(ctx, root_val, segs):
    cur = [root_val]; wild = False
    for seg in segs:
        nxt = []
        for v in cur:
            ctx.tick()
            if seg[0] == "key":
                if isinstance(v, dict) and seg[1] in v: nxt.append(v[seg[1]])
                elif not wild: nxt.append(None)
            elif seg[0] == "idx":
                if isinstance(v, list) and -len(v) <= seg[1] < len(v): nxt.append(v[seg[1]])
                elif not wild: nxt.append(None)
            else:
                items = v if isinstance(v, list) else (list(v.values()) if isinstance(v, dict) else [])
                ctx.tick(len(items)); nxt.extend(items)
        if seg[0] == "star": wild = True
        cur = nxt
    return cur if wild else (cur[0] if cur else None)

def _ev(n, ctx, scope):
    ctx.tick()
    k = n[0]
    if k == "lit": return n[1]
    if k == "list": return [_ev(x, ctx, scope) for x in n[1]]
    if k == "path":
        root = n[1]
        if root in scope: base = scope[root]
        elif root in ctx.roots: base = ctx.roots[root]
        else: base = ctx.res.get(root) if isinstance(ctx.res, dict) else None
        return _walk(ctx, base, n[2])
    if k == "and": return _truthy(_ev(n[1], ctx, scope), "'and'") and _truthy(_ev(n[2], ctx, scope), "'and'")
    if k == "or": return _truthy(_ev(n[1], ctx, scope), "'or'") or _truthy(_ev(n[2], ctx, scope), "'or'")
    if k == "not": return not _truthy(_ev(n[1], ctx, scope), "'not'")
    if k == "cmp":
        op = n[1]; a = _ev(n[2], ctx, scope); b = _ev(n[3], ctx, scope)
        if op == "==": return _eq(a, b)
        if op == "!=": return not _eq(a, b)
        if op in ("in", "not in"):
            if isinstance(b, list): r = any(_eq(a, x) for x in b)
            elif isinstance(b, str): r = isinstance(a, str) and a in b
            elif isinstance(b, dict): r = isinstance(a, str) and a in b
            else: r = False
            return r if op == "in" else not r
        if (_num(a) and _num(b)) or (isinstance(a, str) and isinstance(b, str)):
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        return False
    if k == "quant":
        seq = _ev(n[3], ctx, scope)
        if seq is None: seq = []
        if isinstance(seq, dict): seq = list(seq.values())
        if not isinstance(seq, list): raise RuleError(f"'{n[1]} {n[2]} in' needs a list but got {_tn(seq)}")
        for item in seq:
            ctx.tick()
            r = _truthy(_ev(n[4], ctx, {**scope, n[2]: item}), f"'{n[1]}' body")
            if n[1] == "all" and not r: return False
            if n[1] == "any" and r: return True
        return n[1] == "all"
    if k == "call": return _call(n[1], [_ev(a, ctx, scope) for a in n[2]], ctx)
    raise RuleError("internal: bad node")

def _need_str(v, fn):
    if not isinstance(v, str): raise RuleError(f"{fn}() needs a string but got {_tn(v)}")
    return v

def _call(name, a, ctx):
    if name == "exists": return a[0] is not None
    if name == "len":
        if isinstance(a[0], (list, dict, str)): return len(a[0])
        if a[0] is None: return 0
        raise RuleError(f"len() needs a list, map or string but got {_tn(a[0])}")
    if name == "default": return a[1] if a[0] is None else a[0]
    if name == "keys":
        if a[0] is None: return []
        if not isinstance(a[0], dict): raise RuleError(f"keys() needs a map but got {_tn(a[0])}")
        return sorted(str(x) for x in a[0])
    if name in ("lower", "upper"):
        if a[0] is None: return None
        return _need_str(a[0], name).lower() if name == "lower" else a[0].upper()
    if name in ("startswith", "endswith", "contains"):
        if a[0] is None: return False
        s = _need_str(a[0], name); p = _need_str(a[1], name)
        return s.startswith(p) if name == "startswith" else (s.endswith(p) if name == "endswith" else p in s)
    if name in ("regex", "glob"):
        if a[0] is None: return False
        s = _need_str(a[0], name); p = _need_str(a[1], name)
        if len(s) > MAX_REGEX_SUBJECT: raise RuleError(f"{name}() subject longer than {MAX_REGEX_SUBJECT} characters")
        ctx.tick(len(s) // 8 + 1)
        if name == "regex": return _compiled(p).search(s) is not None
        if len(p) > MAX_REGEX_PATTERN or p.count("*") > MAX_REGEX_QUANTIFIERS: raise RuleError("glob pattern too complex")
        return fnmatch.fnmatchcase(s, p)
    if name in ("cpu", "mem"):
        if a[0] is None: return None
        if isinstance(a[0], bool) or not isinstance(a[0], (str, int, float)): raise RuleError(f"{name}() needs a quantity")
        try: return cpu_millicores(a[0]) if name == "cpu" else memory_bytes(a[0])
        except QuantityError as e: raise RuleError(str(e)) from e
    raise RuleError(f"unknown function {name!r}")

def evaluate(src: str, resource: dict[str, Any]) -> Any:
    """Evaluate one expression against a resource (raises RuleError)."""
    try:
        return _ev(compile_expr(src), _Ctx(resource), {})
    except RecursionError as e:
        raise RuleError("expression too deeply nested") from e

# --------------------------------------------------------------------- rules

@dataclass
class Rule:
    id: str
    title: str
    severity: str
    assert_: str
    category: str = "custom"
    kinds: tuple[str, ...] = ()
    match: str | None = None
    message: str | None = None
    recommendation: str = "Update the manifest to satisfy this custom rule."
    tests: list[dict[str, Any]] = field(default_factory=list)
    source: str = "rules"

def _str(d, key, rid, required=False, maxlen=300):
    v = d.get(key)
    if v is None:
        if required: raise RuleError(f"rule {rid}: '{key}' is required")
        return None
    if not isinstance(v, str) or not v.strip(): raise RuleError(f"rule {rid}: '{key}' must be a non-empty string")
    if len(v) > maxlen: raise RuleError(f"rule {rid}: '{key}' is longer than {maxlen} characters")
    return v

def parse_rules(text: str, source: str = "rules") -> list[Rule]:
    if len(text.encode("utf-8", "replace")) > MAX_FILE_BYTES:
        raise RuleError(f"{source}: rules file larger than {MAX_FILE_BYTES // 1024} KiB")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise RuleError(f"{source}: invalid YAML: {e}") from e
    except RecursionError as e:
        raise RuleError(f"{source}: YAML nested too deeply") from e
    if data is None: return []
    items = data.get("rules") if isinstance(data, dict) and set(data) == {"rules"} else None
    if not isinstance(items, list):
        raise RuleError(f"{source}: expected a mapping with a single 'rules' list")
    if len(items) > MAX_RULES: raise RuleError(f"{source}: more than {MAX_RULES} rules")
    out: list[Rule] = []; seen: set[str] = set()
    for i, d in enumerate(items):
        if not isinstance(d, dict): raise RuleError(f"{source}: rules[{i}] must be a mapping")
        rid = d.get("id")
        m = ID_RE.match(rid) if isinstance(rid, str) else None
        if not m: raise RuleError(f"{source}: rules[{i}].id must look like KF-CUS-001")
        if int(m.group(1)) == 0 or 900 <= int(m.group(1)) <= 999: raise RuleError(f"rule {rid}: ids KF-CUS-000 and KF-CUS-900..999 are reserved")
        if rid in seen: raise RuleError(f"duplicate rule id {rid}")
        seen.add(rid)
        extra = set(d) - RULE_KEYS
        if extra: raise RuleError(f"rule {rid}: unknown key(s) {sorted(map(str, extra))}")
        sev = d.get("severity", "medium")
        if sev not in SEVERITIES: raise RuleError(f"rule {rid}: severity must be one of {', '.join(SEVERITIES)}")
        kinds = d.get("kinds", [])
        if kinds in (None, "*"): kinds = []
        if not isinstance(kinds, list) or not all(isinstance(k, str) and k for k in kinds) or len(kinds) > 50:
            raise RuleError(f"rule {rid}: 'kinds' must be a list of kind names")
        r = Rule(rid, _str(d, "title", rid, True), sev, _str(d, "assert", rid, True, MAX_EXPR_CHARS),
                 _str(d, "category", rid) or "custom", tuple(kinds), _str(d, "match", rid, False, MAX_EXPR_CHARS),
                 _str(d, "message", rid), _str(d, "recommendation", rid) or Rule.recommendation, [], source)
        for label, expr in (("assert", r.assert_), ("match", r.match)):
            if expr is None: continue
            try: compile_expr(expr)
            except RuleError as e: raise RuleError(f"rule {rid}: {label}: {e}") from e
        tests = d.get("tests", []) or []
        if not isinstance(tests, list) or len(tests) > MAX_TESTS_PER_RULE: raise RuleError(f"rule {rid}: 'tests' must be a list of at most {MAX_TESTS_PER_RULE}")
        for j, t in enumerate(tests):
            if not isinstance(t, dict) or set(t) - TEST_KEYS or t.get("expect") not in ("pass", "fail", "skip", "error") or not isinstance(t.get("resource"), dict):
                raise RuleError(f"rule {rid}: tests[{j}] needs 'resource' (mapping) and 'expect' (pass|fail|skip|error); allowed keys {sorted(TEST_KEYS)}")
            r.tests.append({"name": str(t.get("name", f"test {j + 1}")), "expect": t["expect"], "resource": t["resource"]})
        out.append(r)
    return out

def load_rules(paths: list[str | Path]) -> list[Rule]:
    rules: list[Rule] = []
    for p in paths:
        p = Path(p)
        try:
            if p.stat().st_size > MAX_FILE_BYTES: raise RuleError(f"{p}: rules file larger than {MAX_FILE_BYTES // 1024} KiB")
            text = p.read_text(encoding="utf-8")
        except OSError as e:
            raise RuleError(f"cannot read rules file {p}: {e}") from e
        rules += parse_rules(text, str(p))
    ids = [r.id for r in rules]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup: raise RuleError(f"duplicate rule id(s) across files: {sorted(dup)}")
    return rules

def run_rule(rule: Rule, res: dict[str, Any]) -> tuple[str, str]:
    """Returns (pass|fail|skip|error, detail)."""
    kind = res.get("kind") if isinstance(res, dict) else None
    if rule.kinds and kind not in rule.kinds: return "skip", "kind not targeted"
    try:
        if rule.match is not None:
            if not _truthy(evaluate(rule.match, res), "match"): return "skip", "match is false"
        ok = _truthy(evaluate(rule.assert_, res), "assert")
    except RuleError as e:
        return "error", str(e)
    return ("pass", "") if ok else ("fail", rule.message or f"assertion is false: {rule.assert_}")

def rule_findings(resources: list[dict[str, Any]], rules: list[Rule]) -> list[Finding]:
    out: list[Finding] = []
    for o in resources:
        if not isinstance(o, dict) or not o.get("kind"): continue
        rk = resource_key(o)
        for r in rules:
            status, detail = run_rule(r, o)
            if status == "fail":
                out.append(Finding(r.id, r.severity, r.category, r.title, rk, detail[:400], r.recommendation))
            elif status == "error":
                out.append(Finding("KF-CUS-900", "medium", "custom", f"Custom rule {r.id} could not be evaluated", rk, detail[:400],
                                   "Fix the rule expression, or the manifest value it chokes on."))
    return out

def run_rule_tests(rules: list[Rule], require_tests: bool = False) -> list[dict[str, Any]]:
    """Execute embedded tests. Each result: {rule, test, ok, detail}."""
    res = []
    for r in rules:
        if not r.tests and require_tests:
            res.append({"rule": r.id, "test": "(none)", "ok": False, "detail": "rule has no tests"})
        for t in r.tests:
            status, detail = run_rule(r, t["resource"])
            ok = status == t["expect"]
            res.append({"rule": r.id, "test": t["name"], "ok": ok, "detail": "" if ok else f"expected {t['expect']} but got {status}" + (f": {detail}" if detail else "")})
    return res
