"""Tiny KiCad 7 schematic generator: parts are connected by stubs to labels / power symbols."""
import copy, uuid as _uuid, math, json, os
from sexp import Sym, dump, find, find1
from libload import get_symbol, pins as lib_pins, units as lib_units, bbox as lib_bbox

S = Sym
G = 1.27
STUB = 2.54
PROJECT = "openhsm-carrier"

def U():
    return str(_uuid.uuid4())

def snap(v, g=G):
    return round(round(v / g) * g, 4)

def font(sz=1.27):
    return [S("font"), [S("size"), sz, sz]]

def eff(sz=1.27, justify=None, hide=False):
    e = [S("effects"), font(sz)]
    if justify:
        e.append([S("justify")] + [S(j) for j in justify.split()])
    if hide:
        e.append(S("hide"))
    return e

# ------------------------------------------------------------------ custom symbols
CUSTOM = {}

def _pin(num, name, typ, x, y, ang, length=2.54, hide=False):
    p = [S("pin"), S(typ), S("line"), [S("at"), x, y, ang], [S("length"), length]]
    if hide:
        p.append(S("hide"))
    p += [[S("name"), name, eff()], [S("number"), str(num), eff()]]
    return p

def box_symbol(libid, ref, value, left=(), right=(), top=(), bottom=(), width=None,
               description="", footprint="", datasheet=""):
    """left/right/top/bottom: lists of (num, name, type) or None for a gap."""
    name = libid.split(":")[1]
    maxn = max([len(p[1]) for p in list(left) + list(right) + list(top) + list(bottom) if p] + [4])
    if width is None:
        width = snap(max(15.24, (maxn * 2 + 4) * 1.27 * 0.75 + 5.08), 2.54)
    nside = max(len(left), len(right), 1)
    height = snap(max(nside * 2.54 + 2.54, len(top) * 2.54 + 2.54, len(bottom) * 2.54 + 2.54, 7.62), 2.54)
    w2, h2 = snap(width / 2, 2.54), snap(height / 2, 2.54)
    width = max(width, (max(len(top), len(bottom)) + 1) * 2.54)
    w2 = snap(width / 2, 2.54)
    body = [S("symbol"), name + "_0_1",
            [S("rectangle"), [S("start"), -w2, h2], [S("end"), w2, -h2],
             [S("stroke"), [S("width"), 0.254], [S("type"), S("default")]],
             [S("fill"), [S("type"), S("background")]]]]
    pl = [S("symbol"), name + "_1_1"]
    y0 = h2 - 2.54
    for i, p in enumerate(left):
        if p:
            pl.append(_pin(p[0], p[1], p[2], -w2 - 2.54, snap(y0 - i * 2.54), 0))
    for i, p in enumerate(right):
        if p:
            pl.append(_pin(p[0], p[1], p[2], w2 + 2.54, snap(y0 - i * 2.54), 180))
    x0 = -snap((len(top) - 1) * 2.54 / 2, 2.54)
    for i, p in enumerate(top):
        if p:
            pl.append(_pin(p[0], p[1], p[2], snap(x0 + i * 2.54), h2 + 2.54, 270))
    x0 = -snap((len(bottom) - 1) * 2.54 / 2, 2.54)
    for i, p in enumerate(bottom):
        if p:
            pl.append(_pin(p[0], p[1], p[2], snap(x0 + i * 2.54), -h2 - 2.54, 90))
    sym = [S("symbol"), name, [S("in_bom"), S("yes")], [S("on_board"), S("yes")],
           [S("property"), "Reference", ref, [S("at"), -w2, h2 + 1.27, 0], eff(justify="left bottom")],
           [S("property"), "Value", value, [S("at"), -w2, -h2 - 1.27, 0], eff(justify="left top")],
           [S("property"), "Footprint", footprint, [S("at"), 0, 0, 0], eff(hide=True)],
           [S("property"), "Datasheet", datasheet, [S("at"), 0, 0, 0], eff(hide=True)],
           [S("property"), "ki_description", description, [S("at"), 0, 0, 0], eff(hide=True)],
           body, pl]
    CUSTOM[libid] = sym
    return libid

def power_symbol(net, ground=False):
    libid = "openhsm_power:" + net
    if libid in CUSTOM:
        return libid
    if ground:
        g = [S("polyline"), [S("pts"), [S("xy"), 0, 0], [S("xy"), 0, -1.27], [S("xy"), 1.27, -1.27],
                               [S("xy"), 0, -2.54], [S("xy"), -1.27, -1.27], [S("xy"), 0, -1.27]],
             [S("stroke"), [S("width"), 0], [S("type"), S("default")]], [S("fill"), [S("type"), S("none")]]]
        vat = [S("at"), 0, -3.81, 0]
    else:
        g = [S("polyline"), [S("pts"), [S("xy"), -0.762, 1.27], [S("xy"), 0, 2.54], [S("xy"), 0.762, 1.27]],
             [S("stroke"), [S("width"), 0], [S("type"), S("default")]], [S("fill"), [S("type"), S("none")]]]
        g2 = [S("polyline"), [S("pts"), [S("xy"), 0, 0], [S("xy"), 0, 2.54]],
              [S("stroke"), [S("width"), 0], [S("type"), S("default")]], [S("fill"), [S("type"), S("none")]]]
        vat = [S("at"), 0, 3.556, 0]
    sub0 = [S("symbol"), net + "_0_1", g] + ([] if ground else [g2])
    sub1 = [S("symbol"), net + "_1_1",
            [S("pin"), S("power_in"), S("line"), [S("at"), 0, 0, 90 if not ground else 270], [S("length"), 0], S("hide"),
             [S("name"), net, eff()], [S("number"), "1", eff()]]]
    sym = [S("symbol"), net, [S("power")], [S("pin_names"), [S("offset"), 0]],
           [S("in_bom"), S("yes")], [S("on_board"), S("yes")],
           [S("property"), "Reference", "#PWR", [S("at"), 0, -6.35, 0], eff(hide=True)],
           [S("property"), "Value", net, vat, eff()],
           [S("property"), "Footprint", "", [S("at"), 0, 0, 0], eff(hide=True)],
           [S("property"), "Datasheet", "", [S("at"), 0, 0, 0], eff(hide=True)],
           [S("property"), "ki_description", "Power rail " + net, [S("at"), 0, 0, 0], eff(hide=True)],
           sub0, sub1]
    CUSTOM[libid] = sym
    return libid

def lib_symbol(libid):
    if libid in CUSTOM:
        return copy.deepcopy(CUSTOM[libid])
    return get_symbol(libid)

# ------------------------------------------------------------------ geometry
DIRV = {0: (-1, 0), 180: (1, 0), 90: (0, 1), 270: (0, -1)}  # outward direction in DISPLAY coords for lib pin angle

def xform(px, py, rot):
    """lib (y up) -> display offset (y down) for symbol rotation rot (KiCad: CCW on screen)."""
    x, y = px, -py
    r = rot % 360
    if r == 0:
        return x, y
    if r == 90:
        return y, -x
    if r == 180:
        return -x, -y
    if r == 270:
        return -y, x

def rot_dir(d, rot):
    return xform(d[0], -d[1], rot)

# ------------------------------------------------------------------ sheet
class Part:
    def __init__(self, sheet, libid, ref, value, x, y, unit=1, rot=0, footprint=None, fields=None, dnp=False):
        self.sheet, self.libid, self.ref, self.value = sheet, libid, ref, value
        self.x, self.y, self.unit, self.rot = snap(x, 2.54), snap(y, 2.54), unit, rot
        self.footprint, self.fields, self.dnp = footprint, fields or {}, dnp
        self.sym = sheet.need(libid)
        self.allpins = [p for p in lib_pins(self.sym) if p["unit"] in (0, unit)]

    def pin(self, key):
        c = [p for p in self.allpins if p["number"] == key]
        if not c:
            c = [p for p in self.allpins if p["name"] == key]
        if not c:
            raise KeyError("%s: no pin %r" % (self.ref, key))
        return c

    def pin_pos(self, p):
        dx, dy = xform(p["x"], p["y"], self.rot)
        od = rot_dir(DIRV[p["angle"]], self.rot)
        return (snap(self.x + dx), snap(self.y + dy)), (round(od[0]), round(od[1]))


class Sheet:
    def __init__(self, fname, title, paper="A2", page=1):
        self.fname, self.title, self.paper = fname, title, paper
        self.uuid = U()
        self.items = []
        self.libs = {}
        self.parts = []
        self.pwr_n = 0
        self.nc_pins = set()
        self.globals = set()
        self.sheet_uuid = None   # set by project
        self.page = page
        self.nets_here = set()
        self.ptext = []

    def need(self, libid):
        if libid not in self.libs:
            self.libs[libid] = lib_symbol(libid)
        return self.libs[libid]

    # -------------------------------------------------------------- primitives
    def wire(self, a, b):
        if a == b:
            return
        self.items.append([S("wire"), [S("pts"), [S("xy"), a[0], a[1]], [S("xy"), b[0], b[1]]],
                           [S("stroke"), [S("width"), 0], [S("type"), S("default")]], [S("uuid"), U()]])

    def label(self, net, at, d, glob=False):
        self.items.append(("LABEL", net, at, d))
        self.nets_here.add(net)

    def _label_sx(self, net, at, d, glob):
        ang = {(-1, 0): 180, (1, 0): 0, (0, -1): 90, (0, 1): 270}[d]
        just = "left" if ang in (0, 90) else "right"
        if glob:
            return ([S("global_label"), net, [S("shape"), S("bidirectional")], [S("at"), at[0], at[1], ang],
                               [S("fields_autoplaced")], eff(justify=just), [S("uuid"), U()],
                               [S("property"), "Intersheetrefs", "${INTERSHEET_REFS}", [S("at"), at[0], at[1], 0],
                                eff(justify=just, hide=True)]])
        else:
            return [S("label"), net, [S("at"), at[0], at[1], ang], [S("fields_autoplaced")],
                    eff(justify=just + " bottom"), [S("uuid"), U()]]

    def _label_item(self, net, at, d, glob):
        return self._label_sx(net, at, d, glob)

    def power(self, net, at, d):
        ground = net in ("GND", "GND_TAMPER", "PGND", "GNDA", "GND_CHASSIS")
        libid = power_symbol(net, ground)
        self.need(libid)
        if ground:
            rot = {(0, 1): 0, (0, -1): 180, (1, 0): 90, (-1, 0): 270}[d]
        else:
            rot = {(0, -1): 0, (0, 1): 180, (-1, 0): 90, (1, 0): 270}[d]
        self.pwr_n += 1
        ref = "#PWR%s%03d" % (self.fname[:3].upper(), self.pwr_n)
        node = self._place(libid, ref, net, at[0], at[1], 1, rot, "", {}, [("1", None)], hide_ref=True)
        # value text: horizontal, just beyond the symbol in the outward direction
        fa = {0: 0, 180: 0, 90: 270, 270: 90}[rot]  # keeps text horizontal and readable
        if d[0] != 0:
            tx, ty = at[0] + d[0] * 3.8, at[1]
            just = "left" if d[0] > 0 else "right"
        else:
            tx, ty = at[0], at[1] + d[1] * (3.6 if not ground else 4.2) + (0.6 if d[1] > 0 else 0)
            just = None
        if not ground:
            w = text_len(net) - 1.0
            def box(tx, ty):
                if just == "left":
                    return (tx, ty - 0.8, tx + w, ty + 0.8)
                if just == "right":
                    return (tx - w, ty - 0.8, tx, ty + 0.8)
                return (tx - w / 2, ty - 0.8, tx + w / 2, ty + 0.8)
            def hit(b):
                return any(not (b[2] < o[0] or b[0] > o[2] or b[3] < o[1] or b[1] > o[3]) for o in self.ptext)
            n = 0
            while hit(box(tx, ty)) and n < 6:
                if d[1] != 0:
                    ty += d[1] * 1.9
                else:
                    ty += 1.9 if n % 2 == 0 else -1.9 * (n + 1)
                n += 1
            self.ptext.append(box(tx, ty))
        for pr in find(node, "property"):
            if pr[1] == "Value":
                pr[3] = [S("at"), snap(tx, 0.01), snap(ty, 0.01), fa]
                pr[4] = eff(justify=just, hide=ground)

    def no_connect(self, at):
        self.items.append([S("no_connect"), [S("at"), at[0], at[1]], [S("uuid"), U()]])

    def text(self, s, x, y, size=1.27, bold=False):
        e = [S("effects"), [S("font"), [S("size"), size, size]] + ([S("bold")] if bold else []),
             [S("justify"), S("left"), S("bottom")]]
        self.items.append([S("text"), s, [S("at"), snap(x), snap(y), 0], e, [S("uuid"), U()]])

    def rect(self, x1, y1, x2, y2):
        self.items.append([S("rectangle"), [S("start"), x1, y1], [S("end"), x2, y2],
                           [S("stroke"), [S("width"), 0], [S("type"), S("dash")]],
                           [S("fill"), [S("type"), S("none")]], [S("uuid"), U()]])

    def _place(self, libid, ref, value, x, y, unit, rot, footprint, fields, pinlist, hide_ref=False, dnp=False):
        sym = self.libs[libid]
        props = {p[1]: p for p in find(sym, "property")}
        def prop(k, v, dx, dy, hide=False):
            return [S("property"), k, v, [S("at"), snap(x + dx), snap(y + dy), 0], eff(justify="left", hide=hide)]
        node = [S("symbol"), [S("lib_id"), libid], [S("at"), x, y, rot], [S("unit"), unit],
                [S("in_bom"), S("yes")], [S("on_board"), S("yes")], [S("dnp"), S("yes") if dnp else S("no")],
                [S("uuid"), U()]]
        self._last_props = node
        if hide_ref:
            node.append(prop("Reference", ref, 0, 3, hide=True))
            vy = 3.81 if value not in ("GND",) and not value.startswith("GND") else 4.5
            isg = value.startswith("GND")
            node.append([S("property"), "Value", value, [S("at"), x, y, 0], eff(hide=isg)])
        else:
            node.append(prop("Reference", ref, 0, 0))
            node.append(prop("Value", value, 0, 0))
        fp = footprint if footprint is not None else (props["Footprint"][2] if "Footprint" in props else "")
        node.append(prop("Footprint", fp, 0, 0, hide=True))
        ds = props["Datasheet"][2] if "Datasheet" in props else ""
        node.append(prop("Datasheet", ds, 0, 0, hide=True))
        for k, v in fields.items():
            node.append(prop(k, v, 0, 0, hide=True))
        for num, _ in pinlist:
            node.append([S("pin"), num, [S("uuid"), U()]])
        node.append([S("instances"), [S("project"), PROJECT,
                     [S("path"), "/__ROOT__" + ("" if self.sheet_uuid is None else "/" + "__SHEET_%s__" % self.fname),
                      [S("reference"), ref], [S("unit"), unit]]]])
        self.items.append(node)
        return node

    # -------------------------------------------------------------- parts
    def add(self, libid, ref, value, x, y, nets, unit=1, rot=0, footprint=None, fields=None, dnp=False,
            stub=STUB, glob=None, label_refpos="auto"):
        """nets: {pin number or name: net}. Net 'NC' -> no-connect flag. All visible pins must be listed."""
        p = Part(self, libid, ref, value, x, y, unit, rot, footprint, fields, dnp)
        if libid == "power:PWR_FLAG":
            FLAGGED.update(nets.values())
        used = set()
        ends = []   # (end, d, net)
        donepos = set()
        for key, net in nets.items():
            for pin in p.pin(key):
                used.add(pin["number"])
                (px, py), d = p.pin_pos(pin)
                if (px, py) in donepos:
                    continue          # stacked pins share one stub
                donepos.add((px, py))
                if net == "NC":
                    self.no_connect((px, py))
                    self.nc_pins.add((ref, pin["number"]))
                    continue
                end = (snap(px + d[0] * stub), snap(py + d[1] * stub))
                self.wire((px, py), end)
                ends.append((end, d, net))
        # group adjacent same-rail stub ends on one line: one bus wire + one power symbol
        lines = {}
        for e in ends:
            (x, y), d, net = e
            key = (d, x if d[0] != 0 else y)
            lines.setdefault(key, []).append(e)
        # NC flags on the pin line do not sit on the stub-end line, so only stub ends matter here
        for key, es in lines.items():
            d = key[0]
            along = (lambda e: e[0][1]) if d[0] != 0 else (lambda e: e[0][0])
            es.sort(key=along)
            runs, cur = [], [es[0]]
            for e in es[1:]:
                if e[2] == cur[-1][2] and e[2] in RAILS and abs(along(e) - along(cur[-1])) <= 2.55:
                    cur.append(e)
                else:
                    runs.append(cur); cur = [e]
            runs.append(cur)
            for run in runs:
                net = run[0][2]
                if net in RAILS:
                    for a, b in zip(run, run[1:]):
                        self.wire(a[0], b[0])
                    for e in run[1:-1]:
                        self.items.append([S("junction"), [S("at"), e[0][0], e[0][1]], [S("diameter"), 0],
                                           [S("color"), 0, 0, 0, 0], [S("uuid"), U()]])
                    anchor = run[-1] if net.startswith("GND") else run[0]
                    if len(run) > 1:
                        self.items.append([S("junction"), [S("at"), anchor[0][0], anchor[0][1]], [S("diameter"), 0],
                                           [S("color"), 0, 0, 0, 0], [S("uuid"), U()]])
                    self.power(net, anchor[0], d)
                else:
                    for e in run:
                        g = (net in GLOBAL_NETS) if glob is None else glob
                        self.label(e[2], e[0], d, glob=g)
        missing = [q for q in p.allpins if q["number"] not in used and not q["hidden"] and q["type"] != "no_connect"]
        if missing:
            raise ValueError("%s (%s): unassigned pins %s" % (ref, libid, [(q["number"], q["name"]) for q in missing]))
        # hidden no_connect pins / NC-type pins: ignore. hidden other pins: check they coincide with a used pin
        usedpos = set(p.pin_pos(q)[0] for q in p.allpins if q["number"] in used)
        for q in p.allpins:
            if q["hidden"] and q["type"] != "no_connect" and q["number"] not in used:
                if p.pin_pos(q)[0] not in usedpos:
                    raise ValueError("%s hidden pin %s %s not stacked" % (ref, q["number"], q["name"]))
        pinlist = [(q["number"], None) for q in p.allpins]
        seen = set(); pl = []
        for n, _ in pinlist:
            if n not in seen:
                seen.add(n); pl.append((n, None))
        node = self._place(libid, ref, value, p.x, p.y, unit, rot, p.footprint, p.fields, pl, dnp=dnp,
                           hide_ref=ref.startswith("#"))
        # place ref/value text near body
        bb = lib_bbox(p.sym, unit)
        corners = [xform(bb[0], bb[1], rot), xform(bb[2], bb[3], rot)]
        minx = min(c[0] for c in corners); maxx = max(c[0] for c in corners)
        miny = min(c[1] for c in corners); maxy = max(c[1] for c in corners)
        refp = find(node, "property")
        fa = {0: 0, 180: 0, 90: 270, 270: 90}[rot]
        small = (maxx - minx) < 12 and (maxy - miny) < 12
        for pr in refp:
            if small:
                # two-pin passives: put ref/value to the right of the body
                if pr[1] == "Reference":
                    pr[3] = [S("at"), snap(p.x + maxx + 1.0, 0.01), snap(p.y - 0.6, 0.01), fa]
                if pr[1] == "Value":
                    pr[3] = [S("at"), snap(p.x + maxx + 1.0, 0.01), snap(p.y + 1.6, 0.01), fa]
                if rot in (90, 270) and pr[1] in ("Reference", "Value"):
                    yy = miny - (2.2 if pr[1] == "Reference" else 0.6)
                    pr[3] = [S("at"), snap(p.x - 2.5, 0.01), snap(p.y + yy - 0.3, 0.01), fa]
            else:
                if pr[1] == "Reference":
                    pr[3] = [S("at"), snap(p.x + minx + 0.5, 0.01), snap(p.y + miny - 0.8, 0.01), fa]
                if pr[1] == "Value":
                    pr[3] = [S("at"), snap(p.x + minx + 0.5, 0.01), snap(p.y + maxy + 2.0, 0.01), fa]
        self.parts.append(p)
        return p

    # -------------------------------------------------------------- output
    def sexpr(self, root_uuid, sheet_uuid):
        libs = []
        for lid, s in self.libs.items():
            s2 = copy.deepcopy(s)
            s2[1] = lid
            libs.append(s2)
        out = [S("kicad_sch"), [S("version"), 20230121], [S("generator"), S("eeschema")],
               [S("uuid"), self.uuid], [S("paper"), self.paper],
               [S("title_block"), [S("title"), self.title], [S("date"), "2026-11-25"], [S("rev"), "0.2"],
                [S("company"), "OpenHSM"], [S("comment"), 1, "Generated from the openHSM repo docs (v0.6.x). Draft for review."]],
               [S("lib_symbols")] + libs]
        path = "/" + root_uuid + ("" if sheet_uuid is None else "/" + sheet_uuid)
        items = []
        for it in self.items:
            if isinstance(it, tuple) and it[0] == "LABEL":
                net, at, d = it[1], it[2], it[3]
                items.append(self._label_item(net, at, d, net in GLOBAL_NETS))
            else:
                items.append(it)
        txt = dump(out + items)
        txt = txt.replace('"/__ROOT__/__SHEET_%s__"' % self.fname, '"%s"' % path).replace('"/__ROOT__"', '"%s"' % path)
        return txt


def text_len(s, sz=1.27):
    return len(s) * sz * 0.85 + 1.5


class Flow:
    """Places parts left-to-right in rows inside a region, using label-aware extents."""
    def __init__(self, sheet, x0, y0, x1, title=None, gap=5.08):
        self.sh, self.x0, self.y0, self.x1, self.gap = sheet, x0, y0, x1, gap
        if title:
            sheet.text(title, x0, y0, size=2.0, bold=True)
            y0 += 6
        self.cx, self.cy, self.rowh = x0, y0, 0
        self.top = y0
        self.maxy = y0

    def extent(self, libid, unit, rot, nets):
        sh = self.sh
        p = Part(sh, libid, "X", "", 0, 0, unit, rot)
        bb = lib_bbox(p.sym, unit)
        cs = [xform(bb[0], bb[1], rot), xform(bb[2], bb[3], rot)]
        minx = min(c[0] for c in cs); maxx = max(c[0] for c in cs)
        miny = min(c[1] for c in cs) - 2.5; maxy = max(c[1] for c in cs) + 3.0
        for key, net in nets.items():
            for pin in p.pin(key):
                (px, py), d = p.pin_pos(pin)
                L = STUB + (0 if net == "NC" else ((4.0 + (text_len(net) if d[0] != 0 else 2.0)) if net in RAILS
                                                    else text_len(net) + (2.5 if net in GLOBAL_NETS else 0)))
                ex, ey = px + d[0] * L, py + d[1] * L
                if d[1] != 0:
                    half = (text_len(net) / 2 + 0.5) if net in RAILS and not net.startswith("GND") else 1.5
                    if net not in RAILS and net != "NC":
                        half = 1.5
                    ex0, ex1 = px - half, px + half
                    minx = min(minx, ex0); maxx = max(maxx, ex1)
                minx = min(minx, ex); maxx = max(maxx, ex); miny = min(miny, ey); maxy = max(maxy, ey)
        return minx, miny, maxx, maxy

    def place(self, libid, ref, value, nets, unit=1, rot=0, **kw):
        mnx, mny, mxx, mxy = self.extent(libid, unit, rot, nets)
        w, h = mxx - mnx, mxy - mny
        if self.cx + w > self.x1 and self.cx > self.x0:
            self.newrow()
        x = snap(self.cx - mnx, 2.54); y = snap(self.cy - mny, 2.54)
        part = self.sh.add(libid, ref, value, x, y, nets, unit=unit, rot=rot, **kw)
        self.cx = x + mxx + self.gap
        self.rowh = max(self.rowh, h)
        self.maxy = max(self.maxy, y + mxy)
        return part

    def newrow(self):
        self.cx = self.x0
        self.cy = self.cy + self.rowh + self.gap
        self.rowh = 0

    def bottom(self):
        return self.maxy


RAILS = set()
FLAGGED = set()
GLOBAL_NETS = set()


class Project:
    def __init__(self, name, outdir):
        self.name, self.outdir = name, outdir
        self.root = Sheet(name + ".kicad_sch", "OpenHSM carrier: top level", paper="A3")
        self.subs = []

    def add_sheet(self, sheet, x, y, w=50.8, h=25.4):
        sheet.sheet_uuid = U()
        self.subs.append((sheet, x, y, w, h))

    def write(self):
        os.makedirs(self.outdir, exist_ok=True)
        root_uuid = self.root.uuid
        items = []
        for i, (sh, x, y, w, h) in enumerate(self.subs):
            items.append([S("sheet"), [S("at"), x, y], [S("size"), w, h], [S("fields_autoplaced")],
                          [S("stroke"), [S("width"), 0.1524], [S("type"), S("solid")]],
                          [S("fill"), [S("color"), 0, 0, 0, 0.0]], [S("uuid"), sh.sheet_uuid],
                          [S("property"), "Sheetname", sh.title, [S("at"), x, snap(y - 0.7, 0.01), 0], eff(justify="left bottom")],
                          [S("property"), "Sheetfile", sh.fname, [S("at"), x, snap(y + h + 0.6, 0.01), 0], eff(justify="left top")],
                          [S("instances"), [S("project"), PROJECT, [S("path"), "/" + root_uuid, [S("page"), str(i + 2)]]]]])
        self.root.items = self.root.items + items
        txt = self.root.sexpr(root_uuid, None)
        txt = txt.rstrip()[:-1] + '  (sheet_instances\n    (path "/" (page "1"))\n  )\n)\n'
        open(os.path.join(self.outdir, self.root.fname), "w").write(txt)
        for sh, *_ in self.subs:
            open(os.path.join(self.outdir, sh.fname), "w").write(sh.sexpr(root_uuid, sh.sheet_uuid) + "\n")
        pro = {"meta": {"filename": self.name + ".kicad_pro", "version": 1},
               "schematic": {"legacy_lib_dir": "", "legacy_lib_list": []},
               "sheets": [[self.root.uuid, ""]] + [[sh.sheet_uuid, sh.title] for sh, *_ in self.subs],
               "boards": [], "libraries": {"pinned_footprint_libs": [], "pinned_symbol_libs": []},
               "text_variables": {}}
        open(os.path.join(self.outdir, self.name + ".kicad_pro"), "w").write(json.dumps(pro, indent=2))
        json.dump(sorted(FLAGGED), open("/tmp/flagged.json", "w"))
