"""Load KiCad library symbols, flatten 'extends', and describe pins."""
import copy, os
from sexp import parse, find, find1, Sym

LIBDIR = "/usr/share/kicad/symbols"
_cache = {}

def _lib(name):
    if name not in _cache:
        tree = parse(open(os.path.join(LIBDIR, name + ".kicad_sym")).read())
        _cache[name] = {e[1]: e for e in find(tree, "symbol")}
    return _cache[name]

def get_symbol(libid):
    """Return flattened symbol s-expr named 'lib:name' (deep copy)."""
    lib, name = libid.split(":", 1)
    syms = _lib(lib)
    s = copy.deepcopy(syms[name])
    ext = find1(s, "extends")
    if ext:
        parent = get_symbol(lib + ":" + ext[1])
        pname = parent[1]
        # child's properties override parent's
        props = {p[1]: p for p in find(s, "property")}
        out = [Sym("symbol"), name]
        for e in parent[2:]:
            if isinstance(e, list) and e[0] == "property" and e[1] in props:
                out.append(props.pop(e[1]))
            elif isinstance(e, list) and e[0] == "symbol":
                sub = copy.deepcopy(e)
                sub[1] = sub[1].replace(pname, name, 1)
                out.append(sub)
            else:
                out.append(e)
        for p in props.values():
            out.insert(-1, p)
        s = out
    return s

def pins(sym):
    """List of dicts: unit, number, name, type, x, y, angle, length, hidden, alts."""
    res = []
    name = sym[1]
    for sub in find(sym, "symbol"):
        suffix = sub[1][len(name) + 1:]
        unit = int(suffix.split("_")[0])
        for p in find(sub, "pin"):
            at = find1(p, "at")
            nm = find1(p, "name")
            nu = find1(p, "number")
            alts = [a[1] for a in find(p, "alternate")]
            res.append(dict(unit=unit, number=nu[1], name=nm[1], type=str(p[1]),
                            x=float(at[1]), y=float(at[2]), angle=int(float(at[3])),
                            length=float(find1(p, "length")[1]),
                            hidden=any(isinstance(e, Sym) and e == "hide" for e in p),
                            alts=alts))
    return res

def units(sym):
    us = set()
    name = sym[1]
    for sub in find(sym, "symbol"):
        u = int(sub[1][len(name) + 1:].split("_")[0])
        if u:
            us.add(u)
    return sorted(us) or [1]

def bbox(sym, unit):
    """Rough bounding box (lib coords, y up) of body graphics + pins for a unit."""
    xs, ys = [], []
    name = sym[1]
    for sub in find(sym, "symbol"):
        u = int(sub[1][len(name) + 1:].split("_")[0])
        if u not in (0, unit):
            continue
        for g in sub[2:]:
            if not isinstance(g, list):
                continue
            if g[0] == "rectangle":
                for k in ("start", "end"):
                    e = find1(g, k); xs.append(float(e[1])); ys.append(float(e[2]))
            elif g[0] == "polyline":
                for xy in find(find1(g, "pts"), "xy"):
                    xs.append(float(xy[1])); ys.append(float(xy[2]))
            elif g[0] == "circle":
                c = find1(g, "center"); r = float(find1(g, "radius")[1])
                xs += [float(c[1]) - r, float(c[1]) + r]; ys += [float(c[2]) - r, float(c[2]) + r]
            elif g[0] == "pin":
                at = find1(g, "at"); xs.append(float(at[1])); ys.append(float(at[2]))
    if not xs:
        return (-2.54, -2.54, 2.54, 2.54)
    return (min(xs), min(ys), max(xs), max(ys))
