"""Minimal S-expression reader/writer for KiCad files."""
import re

class Sym(str):
    """Bare atom (unquoted)."""
    pass

_tok = re.compile(r'\s*(\(|\)|"(?:[^"\\]|\\.)*"|[^\s()"]+)', re.S)

def parse(text):
    stack = [[]]
    pos = 0
    n = len(text)
    while pos < n:
        m = _tok.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise ValueError("bad token at %d" % pos)
        t = m.group(1)
        pos = m.end()
        if t == "(":
            stack.append([])
        elif t == ")":
            x = stack.pop()
            stack[-1].append(x)
        elif t.startswith('"'):
            stack[-1].append(t[1:-1].replace('\\"', '"').replace("\\\\", "\\"))
        else:
            stack[-1].append(Sym(t))
    return stack[0][0] if len(stack[0]) == 1 else stack[0]

def q(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'

def fmt_atom(a):
    if isinstance(a, Sym):
        return str(a)
    if isinstance(a, bool):
        return "yes" if a else "no"
    if isinstance(a, int):
        return str(a)
    if isinstance(a, float):
        s = ("%.4f" % a).rstrip("0").rstrip(".")
        return "0" if s in ("-0", "") else s
    return q(a)

def dump(x, ind=0):
    if not isinstance(x, list):
        return fmt_atom(x)
    simple = all(not isinstance(e, list) for e in x)
    if simple:
        return "(" + " ".join(fmt_atom(e) for e in x) + ")"
    head = []
    rest = []
    for i, e in enumerate(x):
        if isinstance(e, list):
            rest = x[i:]
            break
        head.append(e)
    s = "(" + " ".join(fmt_atom(e) for e in head)
    for e in rest:
        s += "\n" + "  " * (ind + 1) + dump(e, ind + 1)
    s += "\n" + "  " * ind + ")"
    return s

def find(x, key):
    return [e for e in x if isinstance(e, list) and e and e[0] == key]

def find1(x, key):
    r = find(x, key)
    return r[0] if r else None
