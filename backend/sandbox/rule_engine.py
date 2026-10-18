"""
Minimal evaluator for the plain subset of Elastic EQL used by the Reorg_det_rules corpus.

Supported : `<category> where <expr>`; and / or / not / ( ); == != >= <= > <; `:` ;
            in, in~, like, like~; string/number/null/list literals; dotted ECS fields.
Rejected  : sequence, descendant of / child of, api/library events, field-to-field
            comparison, any rule using Elastic-only `.Ext.` / call-stack / header-byte fields.
            These raise Unsupported at load time and are reported, never silently skipped.
Semantics : `:` and `like~` / `in~` are case-insensitive with * and ? wildcards;
            `==`, `in`, `like` are case-sensitive. Array fields match if ANY element matches.
            A missing field makes a positive comparison False; `!=` on a missing field is True.
"""
from __future__ import annotations
import re, glob, os, tomllib

class Unsupported(Exception):
    pass

_ELASTIC_ONLY = re.compile(r'(\.Ext\.|call_stack|memory_region|header_bytes|api\.name|token\.integrity|code_signature|thread\.Ext)')
_TOKEN = re.compile(r'''\s*(?:
    (?P<cmt>/\*.*?\*/|//[^\n]*)
  | (?P<str>"(?:\\.|[^"\\])*")
  | (?P<num>-?\d+(?:\.\d+)?)
  | (?P<op>==|!=|>=|<=|>|<|:)
  | (?P<lp>\()|(?P<rp>\))|(?P<comma>,)
  | (?P<word>[A-Za-z_][\w.]*~?)
)''', re.X | re.S)

def _tokens(src: str):
    pos, out = 0, []
    src = src.rstrip()
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise Unsupported(f"cannot tokenize near {src[pos:pos+25]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == 'cmt':
            continue
        out.append((kind, m.group(kind)))
    return out

def _unescape(s: str) -> str:
    return re.sub(r'\\(.)', lambda m: {'n': '\n', 't': '\t', 'r': '\r'}.get(m.group(1), m.group(1)), s[1:-1])

def _wild(pattern: str, ci: bool):
    rx = '.*'.join(''.join('.' if c == '?' else re.escape(c) for c in part.replace('*', '')) for part in pattern.split('*'))
    rx = '.*' + rx + '.*'
    return re.compile(rx, re.S | (re.I if ci else 0))

def _get(ev: dict, path: str):
    cur = ev
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def _vals(v):
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]

class _Parser:
    KW = {'and', 'or', 'not', 'in', 'in~', 'like', 'like~', 'null', 'true', 'false'}
    def __init__(self, toks): self.t, self.i = toks, 0
    def peek(self): return self.t[self.i] if self.i < len(self.t) else (None, None)
    def take(self): tok = self.peek(); self.i += 1; return tok
    def isword(self, w): k, v = self.peek(); return k == 'word' and v.lower() == w

    def parse(self):
        fn = self.or_()
        if self.i != len(self.t):
            raise Unsupported(f"trailing tokens at {self.t[self.i:self.i+3]}")
        return fn
    def or_(self):
        parts = [self.and_()]
        while self.isword('or'): self.take(); parts.append(self.and_())
        return (lambda ev: any(p(ev) for p in parts)) if len(parts) > 1 else parts[0]
    def and_(self):
        parts = [self.not_()]
        while self.isword('and'): self.take(); parts.append(self.not_())
        return (lambda ev: all(p(ev) for p in parts)) if len(parts) > 1 else parts[0]
    def not_(self):
        if self.isword('not'):
            self.take(); inner = self.not_(); return lambda ev: not inner(ev)
        return self.primary()
    def primary(self):
        k, v = self.peek()
        if k == 'lp':
            self.take(); fn = self.or_()
            if self.take()[0] != 'rp': raise Unsupported("missing )")
            return fn
        if k == 'word' and v.lower() in ('true', 'false'):
            self.take(); r = v.lower() == 'true'; return lambda ev: r
        if k != 'word' or v.lower() in self.KW:
            raise Unsupported(f"unexpected token {v!r}")
        field = self.take()[1]
        if field.lower() in ('descendant', 'child', 'event') and self.isword('of'):
            raise Unsupported("descendant/child of")
        k2, op = self.take()
        if k2 == 'word': op = op.lower()
        elif k2 != 'op': raise Unsupported(f"expected operator after {field}, got {op!r}")
        rhs = self.value()
        return self.compare(field, op, rhs)
    def value(self):
        k, v = self.take()
        if k == 'str': return [_unescape(v)]
        if k == 'num': return [float(v) if '.' in v else int(v)]
        if k == 'word' and v.lower() == 'null': return [None]
        if k == 'lp':
            items = []
            while True:
                items += self.value()
                k2, _ = self.take()
                if k2 == 'rp': return items
                if k2 != 'comma': raise Unsupported("bad list")
        raise Unsupported(f"unsupported value token {v!r} (field-to-field comparison?)")

    def compare(self, field, op, rhs):
        if op == ':' or op == 'like~' or op == 'like' or op == 'in~':
            ci = op != 'like'
            if op == 'in~': 
                lows = {str(x).lower() for x in rhs}
                return lambda ev: any(str(x).lower() in lows for x in _vals(_get(ev, field)))
            rx = [(_wild(x, ci) if isinstance(x, str) else x) for x in rhs]
            def f(ev):
                for val in _vals(_get(ev, field)):
                    for r in rx:
                        if hasattr(r, 'fullmatch'):
                            if r.fullmatch(str(val)): return True
                        elif val == r: return True
                return False
            return f
        if op == 'in':
            return lambda ev: any(x in rhs for x in _vals(_get(ev, field)))
        if op == '==':
            if rhs == [None]: return lambda ev: _get(ev, field) is None
            return lambda ev: any(x in rhs for x in _vals(_get(ev, field)))
        if op == '!=':
            if rhs == [None]: return lambda ev: _get(ev, field) is not None
            return lambda ev: not any(x in rhs for x in _vals(_get(ev, field)))
        if op in ('>=', '<=', '>', '<'):
            import operator
            fn = {'>=': operator.ge, '<=': operator.le, '>': operator.gt, '<': operator.lt}[op]
            def f(ev):
                try: return any(fn(float(x), float(rhs[0])) for x in _vals(_get(ev, field)))
                except (TypeError, ValueError): return False
            return f
        raise Unsupported(f"operator {op}")

class Rule:
    def __init__(self, d: dict, path: str):
        r = d['rule']; q = r['query']
        self.id, self.name, self.os_list = r['id'], r['name'], r.get('os_list') or []
        self.path = path
        self.description = r.get('description', '')
        self.version = r.get('version', '')
        self.actions = [a.get('action') for a in d.get('actions', [])]
        self.mitre = [{'tactic': t.get('tactic', {}).get('name'), 'technique': te.get('id'), 'name': te.get('name')}
                      for t in d.get('threat', []) for te in t.get('technique', [])]
        if _ELASTIC_ONLY.search(q): raise Unsupported("needs Elastic-only telemetry fields")
        m = re.match(r'\s*(\w+)\s+where\b(.*)', q, re.S)
        if not m or m.group(1) in ('sequence', 'api', 'library'):
            raise Unsupported(f"event type {q.split()[0]!r}")
        self.category = m.group(1)
        self.fn = _Parser(_tokens(m.group(2))).parse()
    def matches(self, ev: dict) -> bool:
        return (self.category == 'any' or ev.get('_category') == self.category) and self.fn(ev)

def load_rules(root: str, os_name: str = 'windows'):
    rules, skipped, seen = [], {}, set()
    for path in sorted(glob.glob(os.path.join(root, '**', '*.toml'), recursive=True)):
        with open(path, 'rb') as fh: d = tomllib.load(fh)
        rid = d['rule']['id']
        if os_name not in (d['rule'].get('os_list') or []) or rid in seen:
            continue
        seen.add(rid)
        try: rules.append(Rule(d, path))
        except Unsupported as e: skipped[d['rule']['name']] = str(e)
    return rules, skipped

def evaluate(rules, events):
    hits = []
    for ev in events:
        for r in rules:
            try:
                if r.matches(ev):
                    hits.append({'rule_id': r.id, 'rule': r.name, 'mitre': r.mitre,
                                 'prevention_grade': 'kill_process' in r.actions, 'event': ev})
            except Exception:
                pass  # never let one bad rule/event break a scan
    return hits