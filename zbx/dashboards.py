#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the three nodeguard dashboards via the Zabbix API.

Contract:
- Builds "NodeGuard Overview", "NodeGuard Security", and "NodeGuard
  Capacity and Pipeline". Each answers one 2am question and carries a
  legend URL widget pointing at the matching anchor of the notes page the
  Zabbix frontend serves from its own origin.
- Fleet scaling: the host group (--group, default "Nodeguard nodes") is
  the canonical fleet definition, resolved live at run time. Item value
  tiles and gauges are generated per resolved group member; svggraph and
  pie datasets address hosts by pattern (--host-pattern, repeatable; the
  default is the resolved members' VISIBLE names, because Zabbix matches
  dataset host patterns against the visible name) and items by NAME
  pattern; the
  honeycomb is group-addressed over the LLD per-feed item names. Adding a
  host costs one re-run, never a code edit.
- The default run prints the full plan (widgets, resolved hosts, resolved
  and unresolved item keys) and exits 0 WITHOUT writing anything to the
  API. --confirm applies, update-or-create by dashboard name. An
  unresolvable item skips its widget with a loud warning line, never
  silently.
- --rename-legacy runs the phase 4 first step: export the dashboard named
  "Nodeguard" to a local JSON file. It REFUSES to delete it; deletion
  stays a manual runbook step after the side-by-side parity check.
- Token from env ZTOKEN only; --url required; connection failures exit
  with a clear message and no traceback.

Stdlib only.
"""

import argparse
import json
import os
import sys

import lib

DASH_OVERVIEW = "NodeGuard Overview"
DASH_SECURITY = "NodeGuard Security"
DASH_CAPACITY = "NodeGuard Capacity and Pipeline"
LEGACY_DASH = "Nodeguard"
DEFAULT_GROUP = "Nodeguard nodes"
# Same-origin path, not a public URL. The page is the zabbix-dashboard-notes
# ConfigMap in homelab-gitops, mounted as a directory at
# /usr/share/zabbix/notes/ and served by the frontend nginx; its text is
# versioned there alongside the Builders and Gateways sections rather than
# fetched from a third party that can move, rename, or vanish. It did exactly
# that: this pointed at a GitHub Pages asset until the repository moved
# organization on 2026-09-07 and every legend widget broke at once.
DEFAULT_LEGEND = "/notes/dashboard-notes.html"

PASS_PATH_ITEMS = [
    "nodeguard XDP pass rate",
    "nodeguard allowlist pass rate",
    "nodeguard WireGuard pass rate",
    "nodeguard expired pass rate",
    "nodeguard non-IP pass rate",
    "nodeguard parse-fail pass rate",
]

TCP_SANITY_ITEMS = [
    "nodeguard TCP SYN+FIN rate",
    "nodeguard TCP SYN+RST rate",
    "nodeguard TCP NULL rate",
    "nodeguard TCP XMAS rate",
]

# Dials per row on the capacity board; see build_capacity.
GAUGES_PER_ROW = 4

TTL_FRAG_ITEMS = [
    "nodeguard low TTL rate",
    "nodeguard IPv4 fragment rate",
    "nodeguard IPv6 fragment rate",
]


class Ctx:
    """Everything a dashboard builder needs, resolved once."""

    def __init__(self, api, groupid, hosts, patterns, explicit_patterns,
                 legend_url, attack_map_url=""):
        """Resolve and cache everything the dashboard builders share: the
        API client, the fleet group and its member hosts, the graph host
        patterns, the legend URL, and each host's item-key-to-itemid map."""
        self.api = api
        self.groupid = groupid
        self.hosts = hosts                    # [{hostid, host, name}]
        self.patterns = patterns              # host patterns for datasets
        self.explicit_patterns = explicit_patterns
        self.legend_url = legend_url
        self.attack_map_url = attack_map_url
        self.items_by_host = {}               # hostid -> {key: item dict}
        self.warnings = []
        self.resolved = []                    # (visible name, key, itemid)
        self.unresolved = []                  # (visible name, key)
        for h in hosts:
            self.items_by_host[h["hostid"]] = lib.resolve_items(
                api, h["hostid"])

    def item(self, host, key):
        """Full item record ({itemid, value_type, units, name}) or None.

        host is a resolved host dict ({hostid, host, name}); lookup is by
        hostid, reporting labels use the visible name. Tiles need the value
        type to choose decimal places and a value font that the item's
        widest string fits into, so resolution returns the record rather
        than the bare id.
        """
        rec = self.items_by_host.get(host["hostid"], {}).get(key)
        if rec is None:
            self.unresolved.append((host["name"], key))
            self.warnings.append(
                "WARNING: item %s unresolved on host %s; widget skipped"
                % (key, host["name"]))
            return None
        self.resolved.append((host["name"], key, rec["itemid"]))
        return rec

    def itemid(self, host, key):
        """Just the item id, for widgets that need nothing else."""
        rec = self.item(host, key)
        return None if rec is None else rec["itemid"]

    def datasets(self, item_names, shift_base=0):
        """svggraph datasets per the scaling rules: explicit patterns get
        one dataset each with palette colors; the derived default gets
        one dataset per member host with the stable host color. Zabbix
        resolves dataset host patterns against the VISIBLE name, so the
        derived default uses h["name"], never the technical h["host"]."""
        out = []
        if self.explicit_patterns:
            for i, pat in enumerate(self.patterns):
                for j, iname in enumerate(item_names):
                    color = lib.OKABE_ITO[(i + j + shift_base)
                                          % len(lib.OKABE_ITO)]
                    out.append((pat, iname, color))
        else:
            for h in self.hosts:
                for j, iname in enumerate(item_names):
                    out.append((h["name"], iname,
                                lib.host_color(h["name"],
                                               shift_base + j)))
        return out


def kv(field):
    """Build the Zabbix item key for one kv field: nodeguard.kv[<field>]."""
    return "nodeguard.kv[%s]" % field


# --- Tile color rules -----------------------------------------------------
#
# Zabbix colors a value with the highest threshold it is at or above and
# leaves anything below the lowest threshold uncolored. Every rule here
# therefore starts at "0", because the rules that started at "1" rendered a
# healthy zero and a broken zero identically: on the live board
# "kill switch 0" (enforcing, good) and "active blocks 0" (the office
# gateway enforcing nothing) were both plain white tiles.
#
# With a threshold at zero the boards gain a property worth more than any
# single tile: every numeric tile is colored, so "all green" is a state a
# reader can take in at a glance, and an uncolored tile now means no data
# rather than good news.
GREEN, AMBER, RED = lib.GREEN, lib.AMBER, lib.RED

ZERO_GOOD = [("0", GREEN), ("1", RED)]          # any occurrence is a fault
ZERO_GOOD_WARN = [("0", GREEN), ("1", AMBER)]   # worth a look, not a page
NONZERO_GOOD = [("0", RED), ("1", GREEN)]       # zero means not working

TILE_THRESHOLDS = {
    "killswitch": ZERO_GOOD,              # 1 = enforcement latched off
    "prog_match": NONZERO_GOOD,           # 1 = the expected program
    "anomaly_count": ZERO_GOOD,
    "feeds_map_errors": ZERO_GOOD,
    "wd_lifeline_fail": ZERO_GOOD,
    "wd_canary_fail": [("0", GREEN), ("1", AMBER), ("2", RED)],
    "feeds_failed": ZERO_GOOD_WARN,
    "feeds_churn_held": ZERO_GOOD_WARN,
    "feeds_journal_reset": ZERO_GOOD_WARN,
    "rearm_count": ZERO_GOOD_WARN,
    "blocks": NONZERO_GOOD,               # nonzero = actively blocking
    "feeds_enforce": NONZERO_GOOD,
    "feeds_approved": NONZERO_GOOD,       # 0 = no feed promoted, blocks none
    "feeds_entries": NONZERO_GOOD,
    "sweep_age": [("0", GREEN), ("900", AMBER), ("1800", RED)],
}
# fields worth a trend sparkline behind the number
TILE_SPARKLINE = {"blocks", "anomaly_count", "feeds_entries"}


# How wide the rendered string is for units the frontend reformats. A
# unixtime item does not show its number, it shows "2026-09-20 06:58:18 AM";
# a seconds item shows "5m 46s". Sizing either from the raw value would
# oversize the tile and clip it.
RENDERED_CHARS = {"unixtime": len("2026-09-20 06:58:18 AM"),
                  "s": len("9d 23h 59m")}


def rendered_chars(rec, decimals):
    """Characters the frontend will draw for this item's value.

    Uses the item's own last value, so a tile is sized for the data it
    actually carries rather than for a guess: the ranked source lines and
    the country lines share a widget shape but differ by twenty characters,
    and one fixed font size either clips the first or wastes the second.
    """
    units = rec.get("units") or ""
    if units in RENDERED_CHARS:
        return RENDERED_CHARS[units]
    sample = (rec.get("lastvalue") or "").strip()
    if not sample:
        return lib.VALUE_CHARS_FALLBACK
    # Zabbix abbreviates large numbers ("1.7 K"), so a long digit string
    # never renders at its full length.
    n = min(len(sample), 8) if rec["value_type"] in lib.VT_NUMERIC \
        else len(sample)
    if decimals:
        n += 1 + decimals
    if units:
        n += 1 + len(units)
    return n


def tile_fields(rec, height=3, width=12):
    """Presentation for one tile, derived from the item itself.

    Returns (decimals, value_size). An unsigned counter gets no decimal
    places: the Zabbix default of 2 rendered "1691.00" in a tile that then
    had room for neither and clipped it to "1691.0". The value font is
    computed from the string the item actually holds, because the frontend
    ellipsizes the value rather than scaling it to fit.
    """
    vt = rec["value_type"]
    if vt in (lib.VT_CHAR, lib.VT_TEXT):
        decimals = None
    elif rec.get("units") == "unixtime":
        decimals = 0
    else:
        decimals = 0 if vt == lib.VT_UNSIGNED else 1
    size = lib.value_size_for(rendered_chars(rec, decimals or 0),
                              width, height)
    return decimals, size


def tile_row(ctx, widgets, y, host, specs, height=3):
    """One row of item value tiles for one host.

    specs is [(width, label, kv_field), ...]. The label is the METRIC
    alone and becomes the widget header; the host name goes in the tile's
    description, which has the tile's full width. Prefixing the header with
    the host instead spent the entire header budget of a narrow tile before
    the metric was named (see lib.HEADER_GUTTER_PX), which is how a whole
    row came to read "gateway-home: ...".

    Unresolvable tiles are skipped loudly and their slot left empty; a
    label too long for its width is warned about rather than silently
    ellipsized on the board.
    """
    x = 0
    for width, label, field in specs:
        rec = ctx.item(host, kv(field))
        if rec is not None:
            budget = lib.header_chars(width)
            if len(label) > budget:
                ctx.warnings.append(
                    "WARNING: header %r is %d chars but width %d shows "
                    "about %d; it will be ellipsized"
                    % (label, len(label), width, budget))
            decimals, value_size = tile_fields(rec, height, width)
            textual = rec["value_type"] not in lib.VT_NUMERIC
            widgets.append(lib.itemvalue(
                x, y, width, height, label, rec["itemid"],
                thresholds=TILE_THRESHOLDS.get(field, ()),
                sparkline=field in TILE_SPARKLINE,
                description=host["name"],
                desc_size=lib.desc_size_for(len(host["name"]),
                                            width, height),
                decimals=decimals, value_size=value_size,
                bg_color=lib.NEUTRAL if textual else ""))
        x += width
    return y + height


def leaderboard(ctx, widgets, x, y, w, host, title, field_prefix,
                rows=5, row_h=2):
    """A ranked stack for one host: one value tile per rank, so top-blocked
    sources or attacker countries read as a leaderboard instead of a
    crammed string. field_prefix is e.g. "top_blocked" -> top_blocked_1..N.

    Every row carries the full "<title> #N" header, not a bare "#N". Only
    the first row was labelled before, which left four columns of tiles all
    headed "#2" once the first row had scrolled off: no way to tell which
    host or which leaderboard a rank belonged to.

    Rows are short (height 2), and a ranked line is a long string
    ("45.194.92.0/24  61 new (7051 total)"), so the value font comes from
    the item's type at this height rather than the default that clipped it.
    """
    for i in range(1, rows + 1):
        rec = ctx.item(host, kv("%s_%d" % (field_prefix, i)))
        if rec is None:
            continue
        label = "%s #%d" % (title, i)
        budget = lib.header_chars(w)
        if len(label) > budget:
            ctx.warnings.append(
                "WARNING: header %r is %d chars but width %d shows about "
                "%d; it will be ellipsized" % (label, len(label), w, budget))
        _, value_size = tile_fields(rec, row_h, w)
        widgets.append(lib.itemvalue(x, y + (i - 1) * row_h, w, row_h,
                                     label, rec["itemid"],
                                     value_size=value_size))
    return y + rows * row_h


def build_overview(ctx):
    """Is the firewall attached, enforcing, and healthy right now."""
    refs = lib.RefSeq("OV")
    widgets = [lib.url_widget(0, 0, 72, 3,
                              "Legend: how to read this dashboard",
                              ctx.legend_url + "#nodeguard-overview")]
    y = 3
    # Headers carry the metric only; the host is the tile description.
    # "kill switch (0=enforcing)" was 25 characters in a tile that shows
    # about 20, so it read "kill s..."; the sense of the number is now
    # carried by the threshold colors and the legend above.
    tiles = [(12, "firewall attached?", "attach_state"),
             (12, "kill switch", "killswitch"),
             (12, "program identity", "prog_match"),
             (12, "active blocks", "blocks"),
             (12, "responder unit", "responder"),
             (12, "anomaly trips", "anomaly_count")]
    for h in ctx.hosts:
        y = tile_row(ctx, widgets, y, h, tiles)
    graphs = [
        ("XDP drop rate v4 and v6: pkts/s dropped in-driver from "
         "blocklisted sources (attacks stopped)",
         ["nodeguard XDP drop rate v4", "nodeguard XDP drop rate v6"],
         False),
        ("XDP pass rate: internet traffic reaching the blocklist check",
         ["nodeguard XDP pass rate"], False),
        ("Active blocks: block-map population (entries expire in-kernel "
         "by TTL)",
         ["nodeguard active blocks"], False),
        ("Suricata kernel drop rate: sustained nonzero = capture ring "
         "overflow, detection gaps",
         ["suricata kernel drop rate"], False),
        ("Allowlist pass rate: never-blockable sources",
         ["nodeguard allowlist pass rate"], False),
        ("WireGuard pass rate: tunnel traffic hard-passed before any "
         "lookup",
         ["nodeguard WireGuard pass rate"], False),
    ]
    for i, (name, items, stacked) in enumerate(graphs):
        x = (i % 2) * 36
        gy = y + (i // 2) * 7
        widgets.append(lib.svggraph(x, gy, 36, 7, name,
                                    ctx.datasets(items), refs,
                                    stacked=stacked))
    y += ((len(graphs) + 1) // 2) * 7
    for h, (x, w) in zip(ctx.hosts,
                         lib.split_columns(len(ctx.hosts))):
        widgets.append(lib.pie(x, y, w, 7,
                               "%s: pass-path share" % h["name"],
                               h["name"], PASS_PATH_ITEMS))
    return widgets


def build_security(ctx):
    """Are we being scanned or attacked, and is or would the pipeline be
    responding."""
    refs = lib.RefSeq("SE")
    widgets = [lib.url_widget(0, 0, 72, 3,
                              "Legend: how to read this dashboard",
                              ctx.legend_url + "#nodeguard-security")]
    y = 3
    widgets.append(lib.svggraph(
        0, y, 36, 7,
        "TCP sanity scan rates (stacked): SYN+FIN, SYN+RST, NULL, XMAS",
        ctx.datasets(TCP_SANITY_ITEMS), refs, stacked=True))
    widgets.append(lib.svggraph(
        36, y, 36, 7,
        "Low TTL and fragments: evasion probing and fragment noise",
        ctx.datasets(TTL_FRAG_ITEMS), refs))
    y += 7
    widgets.append(lib.svggraph(
        0, y, 72, 8,
        "Alert-to-block story: suricata alert rate vs responder "
        "decisions vs XDP drop rate (dry-run divergence reads directly)",
        ctx.datasets(["suricata alerts rate",
                      "responder dry-run would-block rate",
                      "responder blocks issued rate",
                      "nodeguard XDP drop rate v4",
                      "nodeguard XDP drop rate v6"]), refs))
    y += 8
    # small status strip: one compact row of pipeline-freshness tiles
    tiles = [(18, "last alert seen", "resp_last_alert_ts"),
             (18, "last responder action", "resp_last_action_ts"),
             (18, "watchdog canary failures", "wd_canary_fail"),
             (18, "top blocked hit count", "top1_hits")]
    # The two timestamp tiles render a full datetime; tile_fields gives
    # them a value font that fits width 18 instead of the default that
    # clipped "2026-09-20 06:39:02 AM" to "2026-09-20 0...".
    for h in ctx.hosts:
        y = tile_row(ctx, widgets, y, h, tiles)

    # Leaderboards, full width, one column-pair per host: the top blocked
    # sources (left) and the top attacker countries (right), each as a
    # ranked stack instead of a crammed string.
    ncols = max(1, len(ctx.hosts))
    colw = lib.GRID_COLUMNS // ncols
    for i, h in enumerate(ctx.hosts):
        x0 = i * colw
        half = colw // 2
        leaderboard(ctx, widgets, x0, y, half, h,
                    "%s top blocked" % h["name"], "top_blocked")
        leaderboard(ctx, widgets, x0 + half, y, colw - half, h,
                    "%s top countries" % h["name"], "geo_country")
    return widgets


def build_capacity(ctx):
    """Will anything fill up or go stale before morning."""
    refs = lib.RefSeq("CA")
    widgets = [lib.url_widget(0, 0, 72, 3,
                              "Legend: how to read this dashboard",
                              ctx.legend_url + "#nodeguard-capacity")]
    y = 3
    # Gauges: host in the description, metric in the header, and the
    # threshold arc drawn. Left at the Zabbix default the description is
    # "{ITEM.NAME}", which rendered "nodeguard v4 blo..." in oversized text
    # under every dial, and with no arc a needle resting near zero said
    # nothing about the distance to the 70 and 85 thresholds.
    gauges = []
    for h in ctx.hosts:
        for field, label in (("util_v4_pct", "v4 map fill"),
                             ("util_v6_pct", "v6 map fill")):
            gauges.append((h, field, label))
    # Four dials per row. Dividing the strip by the gauge count instead
    # would keep narrowing them as the fleet grows, and a dial narrower
    # than about 12 columns cannot show its host name; wrapping keeps the
    # widget legible at any fleet size, which is the point of generating
    # it from live membership in the first place.
    gauge_span = lib.GRID_COLUMNS - 24
    slots = lib.split_columns(min(GAUGES_PER_ROW, len(gauges)),
                              total=gauge_span)
    for i, (host, field, label) in enumerate(gauges):
        x, w = slots[i % GAUGES_PER_ROW]
        gy = y + (i // GAUGES_PER_ROW) * 5
        iid = ctx.itemid(host, kv(field))
        if iid is not None:
            widgets.append(lib.gauge(
                x, gy, w, 5, label, iid, description=host["name"],
                desc_size=lib.desc_size_for(len(host["name"]), w, 5),
                thresholds=[("70", "E69F00"), ("85", "D55E00")]))
    # The dials give the instant; the question the board exists to answer
    # ("will anything fill up before morning") is a slope, so the space the
    # fourth dial does not need carries the trend instead.
    widgets.append(lib.svggraph(
        gauge_span, y, lib.GRID_COLUMNS - gauge_span, 5,
        "Block-map fill trend (%)",
        ctx.datasets(["nodeguard v4 block map utilization",
                      "nodeguard v6 block map utilization"]), refs))
    y += 5 * ((len(gauges) + GAUGES_PER_ROW - 1) // GAUGES_PER_ROW)
    # One honeycomb per host, cells labelled by ITEM so the feed is named.
    # A single group-addressed comb labelled "{HOST.NAME}" produced six
    # cells reading "gateway-home"/"gateway-office", three of them amber or
    # red, with no way to tell which feed had gone stale. Generated from
    # live group membership, so a new host still costs no edit.
    for h, (x, w) in zip(ctx.hosts, lib.split_columns(len(ctx.hosts))):
        widgets.append(lib.honeycomb(
            x, y, w, 5,
            "%s: per-feed snapshot age (green under 26h)" % h["name"],
            "feed * snapshot age", hostid=h["hostid"],
            thresholds=[("0", "009E73"), ("93600", "E69F00"),
                        ("172800", "D55E00")]))
    y += 5
    graphs = [
        ("Feeds-owned entries", ["feeds owned entries"]),
        ("Feeds pipeline: candidates vs rejected vs failed",
         ["feeds candidates", "feeds rejected", "feeds failed count"]),
        ("Sweep walk duration: the walk's own degradation, visible "
         "before it hurts",
         ["nodeguard sweep walk duration"]),
    ]
    for i, (name, items) in enumerate(graphs):
        x = (i % 2) * 36
        gy = y + (i // 2) * 7
        widgets.append(lib.svggraph(x, gy, 36, 7, name,
                                    ctx.datasets(items), refs))
    y += ((len(graphs) + 1) // 2) * 7
    # Two rows of width-12 tiles per host rather than one row of width-10.
    # A width-10 tile shows about 15 header characters, which the old
    # "<host>: " prefix consumed on its own; width 12 shows about 20 and
    # every label below fits inside it.
    #
    # feeds approved and feeds owned entries are new. They are the pair
    # that distinguishes "enforcing nothing because there is nothing to
    # block" from "enforcing nothing because no feed was ever promoted",
    # and the second state was invisible on the old board.
    tiles_a = [(12, "feeds enforce", "feeds_enforce"),
               (12, "feeds approved", "feeds_approved"),
               (12, "feeds owned entries", "feeds_entries"),
               (12, "feed failures", "feeds_failed"),
               (12, "map errors", "feeds_map_errors"),
               (12, "churn held", "feeds_churn_held")]
    tiles_b = [(12, "journal reset", "feeds_journal_reset"),
               (12, "re-arm count", "rearm_count"),
               (12, "lifeline failures", "wd_lifeline_fail"),
               (12, "sweep age", "sweep_age")]
    for h in ctx.hosts:
        y = tile_row(ctx, widgets, y, h, tiles_a)
        y = tile_row(ctx, widgets, y, h, tiles_b)
    return widgets


BUILDERS = [
    ("overview", DASH_OVERVIEW, build_overview),
    ("security", DASH_SECURITY, build_security),
    ("capacity", DASH_CAPACITY, build_capacity),
]


def print_plan(ctx, plans):
    """Print the read-only plan: resolved hosts, host patterns, every
    dashboard's widgets, the resolved and unresolved item keys, and any
    warnings, without writing anything to the API."""
    print("== plan (no API writes; use --confirm to apply) ==")
    print("resolved hosts (%d):" % len(ctx.hosts))
    for h in ctx.hosts:
        # Both names printed so a technical-vs-visible divergence is
        # visible in plan mode; dataset patterns match the visible name.
        print("  %s (visible name %r, hostid %s)"
              % (h["host"], h["name"], h["hostid"]))
    print("host patterns for graph datasets (matched against visible "
          "names): %s" % ", ".join(ctx.patterns))
    for name, widgets in plans:
        print("dashboard: %s (%d widgets)" % (name, len(widgets)))
        for w in widgets:
            desc = ""
            for fl in w["fields"]:
                if fl["name"] == "description" and fl["value"]:
                    desc = "  [%s]" % fl["value"]
                    break
            print("  %-10s x=%-2d y=%-2d %dx%-2d %s%s"
                  % (w["type"], w["x"], w["y"], w["width"], w["height"],
                     w["name"], desc))
    if ctx.resolved:
        print("resolved item keys (%d):" % len(ctx.resolved))
        for host, key, iid in ctx.resolved:
            print("  %s %s -> itemid %s" % (host, key, iid))
    if ctx.unresolved:
        print("unresolved item keys (%d):" % len(ctx.unresolved))
        for host, key in ctx.unresolved:
            print("  %s %s" % (host, key))
    for w in ctx.warnings:
        print(w)


def apply_dashboards(api, plans):
    """Write each planned dashboard to Zabbix, updating it in place when one
    of the same name already exists and creating it otherwise."""
    for name, widgets in plans:
        pages = [{"widgets": widgets}]
        existing = api.call("dashboard.get", {"filter": {"name": [name]}})
        if existing:
            api.call("dashboard.update", {
                "dashboardid": existing[0]["dashboardid"],
                "pages": pages})
            print("updated dashboard: %s" % name)
        else:
            api.call("dashboard.create", {
                "name": name, "display_period": 60, "auto_start": 1,
                "pages": pages})
            print("created dashboard: %s" % name)


def export_legacy(api, out_path):
    """Phase 4 first step: export the legacy dashboard to a local file.
    Deletion stays manual per the runbook; this tool refuses to do it."""
    got = api.call("dashboard.get", {
        "filter": {"name": [LEGACY_DASH]},
        "output": "extend", "selectPages": "extend"})
    if not got:
        print("legacy dashboard %r not found; nothing exported"
              % LEGACY_DASH)
        return
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(got[0], fh, indent=1)
    print("exported legacy dashboard %r to %s" % (LEGACY_DASH, out_path))
    print("refusing to delete %r: run the side-by-side parity check "
          "first; deletion stays a manual runbook step" % LEGACY_DASH)


def main():
    """Command-line entry point: resolve the fleet group, build the
    selected dashboards, then either print the plan (default) or apply them
    to the API with --confirm; --rename-legacy exports the old dashboard."""
    ap = argparse.ArgumentParser(
        description="Generate the three NodeGuard dashboards. Default is "
                    "a read-only plan; --confirm applies.")
    ap.add_argument("--url", required=True,
                    help="Zabbix API URL (no default in the public repo)")
    ap.add_argument("--group", default=DEFAULT_GROUP,
                    help="host group naming the fleet (default: %r)"
                         % DEFAULT_GROUP)
    ap.add_argument("--host-pattern", action="append", default=[],
                    help="host pattern for svggraph and pie datasets "
                         "(matched by Zabbix against the VISIBLE host "
                         "name); repeatable; default: the group's "
                         "resolved member visible names")
    ap.add_argument("--legend-url", default=DEFAULT_LEGEND,
                    help="base URL of the notes page (default: the "
                         "same-origin page the frontend serves)")
    ap.add_argument("--attack-map-url", default="",
                    help="URL serving the live attack-origin SVG "
                         "(nodeguard-geo writes it per host; the private "
                         "wrapper supplies where it is served). Omit to "
                         "skip the map widget.")
    ap.add_argument("--dashboard", default="all",
                    choices=["overview", "security", "capacity", "all"],
                    help="which dashboard(s) to build (default: all)")
    ap.add_argument("--confirm", action="store_true",
                    help="apply via the API (update-or-create by "
                         "dashboard name); without it, plan only")
    ap.add_argument("--rename-legacy", action="store_true",
                    help="export the legacy 'Nodeguard' dashboard to a "
                         "local JSON file; never deletes it")
    ap.add_argument("--legacy-export",
                    default=os.path.join("output",
                                         "nodeguard-legacy-dashboard.json"),
                    help="where --rename-legacy writes the export")
    args = ap.parse_args()

    try:
        api = lib.Api(args.url)
        if args.rename_legacy:
            export_legacy(api, args.legacy_export)
        groupid, hosts = lib.resolve_group(api, args.group)
        ctx = Ctx(api, groupid, hosts,
                  args.host_pattern or [h["name"] for h in hosts],
                  bool(args.host_pattern), args.legend_url,
                  args.attack_map_url)
        plans = [(name, builder(ctx))
                 for short, name, builder in BUILDERS
                 if args.dashboard in ("all", short)]
        if args.confirm:
            for w in ctx.warnings:
                print(w)
            apply_dashboards(api, plans)
        else:
            print_plan(ctx, plans)
    except lib.ZabbixError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
