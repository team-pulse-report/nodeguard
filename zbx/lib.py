# SPDX-License-Identifier: MIT
"""Shared library for the nodeguard Zabbix generators.

Contract:
- JSON-RPC client for the Zabbix API (7.4). The auth token comes from the
  environment variable ZTOKEN only; it is never accepted on argv and never
  printed, logged, or echoed in error messages. The API URL is always an
  explicit argument; there is no default URL in this public repository.
- Connection and API failures raise ZabbixError with a clear message so
  callers can fail gracefully without a traceback.
- Fleet resolution per the fleet-scaling rules: a host group name is the
  canonical fleet definition; resolve_group() returns the group id and its
  member hosts live, so widgets that need per-host enumeration are generated
  from the group's current membership at run time.
- Widget builders (itemvalue, gauge, svggraph, pie, honeycomb, url)
  return dashboard widget dicts for dashboard.create/update. svggraph
  and pie datasets address hosts by PATTERN and items by NAME pattern, so a
  new host's items match without a code edit; Zabbix resolves those host
  patterns against the host's VISIBLE name, not the technical name. Field
  names for gauge and honeycomb follow the 7.4 export format and must be
  verified with one plan-mode diff against a hand-exported dashboard before
  the first confirmed apply.
- 72-column grid helpers and the Okabe-Ito palette. host_color() hashes the
  host name into the palette so a host keeps its color when the fleet grows
  or the member list reorders.
- Legibility budgets (HEADER_*, *_SIZE below) are measured against the live
  frontend, never taken from the documentation, because the API validates
  neither field names nor widget types: see the note above the constants.

Stdlib only. No mutation happens in this module beyond api() POSTs the
caller explicitly issues.
"""

import hashlib
import itertools
import json
import os
import urllib.error
import urllib.request

# Zabbix dashboard widget field types.
FIELD_INT = 0
FIELD_STR = 1
FIELD_GROUP = 2
FIELD_HOST = 3
FIELD_ITEM = 4

# Zabbix 7.x dashboards are a 72-column grid.
GRID_COLUMNS = 72

# Okabe-Ito colorblind-safe palette (hex, no leading #), grey substituted
# for black so lines stay visible on the dark theme.
OKABE_ITO = [
    "0072B2",  # blue
    "D55E00",  # vermillion
    "009E73",  # bluish green
    "CC79A7",  # reddish purple
    "E69F00",  # orange
    "56B4E9",  # sky blue
    "F0E442",  # yellow
    "999999",  # grey
]

# Threshold colors shared by the tile, gauge, and honeycomb rules.
GREEN = "81C784"
AMBER = "FFB74D"
RED = "E57373"
# Tiles whose item is textual cannot carry a threshold colour. They get
# this neutral wash instead, so that once every numeric tile is coloured a
# plain white tile means "no data" and nothing else.
NEUTRAL = "ECEFF1"

# --- Legibility budgets ---------------------------------------------------
#
# Every number in this block was measured against the live 7.4.14 frontend
# on 2026-09-20 by rendering a candidate widget beside the incumbent, NOT
# read off the documentation. That is deliberate. The dashboard API
# validates widget geometry and nothing else: dashboard.create accepted a
# deliberately misspelled field name, an out-of-range enum, and a widget of
# type "notawidget" without complaint. A widget that writes cleanly is not
# a widget that renders, so "the API took it" is not evidence here and a
# change to these numbers has to be re-checked by looking at the page.
#
# Widget headers are a fixed 14px bold Arial, ellipsized rather than
# wrapped. Usable header width is the widget's pixel width minus a 72px
# button gutter, and at the measured 1396px grid one column is 19.4px:
#
#     width 10 -> 194px ->  122px usable -> ~15 characters
#     width 12 -> 233px ->  161px usable -> ~20 characters
#     width 18 -> 349px ->  277px usable -> ~35 characters
#     width 24 -> 465px ->  393px usable -> ~49 characters
#
# "gateway-office: " is 16 characters on its own. Prefixing a tile header
# with the host name therefore spent the whole budget of a width-10 tile
# before the metric was named, which is why every tile on the live Capacity
# board read "<host>: ...". Host identity belongs in the widget's own
# description field, which has the full tile width to itself.
HEADER_GUTTER_PX = 72
GRID_PX = 1396.0
COLUMN_PX = GRID_PX / GRID_COLUMNS
HEADER_CHAR_PX = 8.0

# The item *_size fields are a percentage the frontend rescales by widget
# height, so one size does not travel between tile heights, and the value
# font is ellipsized rather than shrunk to fit, so one size does not travel
# between short and long values either. Left at the Zabbix default of 45, a
# width-10 tile clipped "attached" to "atta..." and a width-18 tile clipped
# a timestamp to "2026-09-20 0...". Pinning a small size instead wastes the
# tile: at the size that fits a 35-character ranked line, a 13-character
# country line rendered at a fifth of the room it had.
#
# value_size_for() therefore computes the size from the string the item
# actually holds. Its two calibration constants were measured on the live
# frontend on 2026-09-20 by reading back the rendered font size:
#
#   height 2 tile,  value_size 45 -> 30.39px  => 0.675 px per size unit
#   height 3 tile,  value_size 45 -> 58.03px  => 1.290 px per size unit
#   height 5 gauge, desc_size  13 -> 30.37px  => 2.336 px per size unit
#
# The scale is roughly linear in pixel height but not exactly, so each
# height the boards use is measured rather than interpolated, and a height
# that has not been measured falls back to the Zabbix default instead of
# being guessed at.
#
# and the usable value width is the tile's pixel width less 40px of
# padding (349px width-18 tile measured 309px usable).
VALUE_PX_PER_SIZE = {2: 0.675, 3: 1.290, 5: 2.336}
VALUE_PADDING_PX = 40
# Mean glyph width as a fraction of font size. Lowercase prose is the wide
# case and digits, dots and slashes the narrow one; the wide figure is used
# for both so a value that grows a little does not start clipping. Checked
# against the two measured extremes: "attached" at width 10 clips at size
# 30 and fits at 22, and a 35-character ranked line at width 18 clips at 45
# and fits at 14.
VALUE_CHAR_RATIO = 0.62
VALUE_SAFETY = 0.9
VALUE_SIZE_MAX = 45      # the Zabbix default; nothing needs to shout louder
VALUE_SIZE_MIN = 8       # below this the tile is not worth rendering
# A value can grow after the dashboard is built (a longer CIDR, a bigger
# counter), so size for a string a fifth longer than the one on hand.
VALUE_GROWTH = 1.2
VALUE_CHARS_FALLBACK = 12   # when no sample value is available

DESC_SIZE = 13           # height 3 host-name line: renders 17px
DESC_TARGET_PX = 17      # the host line should read the same on every tile
DESC_SIZE_MIN = 5


def desc_size_for(chars, width, height):
    """Size for a tile's host line: one apparent size on every widget.

    The size fields scale with widget height, so the 13 that renders a
    17px host line on a height-3 tile renders a 30px one on a height-5
    gauge, where it swamped the dial. Target the pixel height instead and
    clamp it to what the width will hold.
    """
    px_per_size = VALUE_PX_PER_SIZE.get(height)
    if px_per_size is None:
        return DESC_SIZE
    usable = max(1.0, width * COLUMN_PX - VALUE_PADDING_PX)
    fits_px = usable / (max(1.0, chars) * VALUE_CHAR_RATIO) * VALUE_SAFETY
    return max(DESC_SIZE_MIN,
               int(min(DESC_TARGET_PX, fits_px) / px_per_size))


def value_size_for(chars, width, height):
    """Largest value font size that shows `chars` characters unclipped.

    chars is the length of the widest string the item is expected to hold,
    width and height are the widget's grid dimensions. Returns a size in
    the 1-100 units the item widget's value_size field takes.
    """
    px_per_size = VALUE_PX_PER_SIZE.get(height)
    if px_per_size is None:
        # Sizes were only calibrated at the two tile heights the boards
        # use; anything else falls back to the Zabbix default rather than
        # guessing, so a new tile shape is visibly ordinary, not subtly
        # mis-sized.
        return None
    usable = max(1.0, width * COLUMN_PX - VALUE_PADDING_PX)
    chars = max(1.0, chars * VALUE_GROWTH)
    font_px = usable / (chars * VALUE_CHAR_RATIO)
    size = int(font_px / px_per_size * VALUE_SAFETY)
    return max(VALUE_SIZE_MIN, min(VALUE_SIZE_MAX, size))


# Sparkline enable. The sparkline is turned on by listing it among the
# widget's shown elements (show.N = 5); "sparkline.show" is not a field.
# Setting only the latter, as this module did until 2026-09-20, is accepted
# by the API and draws nothing.
SHOW_DESCRIPTION = 1
SHOW_VALUE = 2
SHOW_TIME = 3
SHOW_CHANGE = 4
SHOW_SPARKLINE = 5


def header_chars(width):
    """How many header characters a widget of this column width shows.

    Used by the generator's plan output to flag a header that will be
    ellipsized, so the truncation is caught before it is applied rather
    than noticed on the dashboard.
    """
    usable = width * COLUMN_PX - HEADER_GUTTER_PX
    return max(0, int(usable / HEADER_CHAR_PX))


class ZabbixError(Exception):
    """A Zabbix API call failed or could not be issued."""


def host_color(host, shift=0):
    """Stable per-host color: hash of the host name into the palette.

    The assignment depends only on the name, so colors do not shuffle when
    hosts are added to or removed from the group. shift offsets the index
    for a second metric of the same host on one graph.
    """
    idx = int(hashlib.sha256(host.encode()).hexdigest(), 16)
    return OKABE_ITO[(idx + shift) % len(OKABE_ITO)]


def split_columns(n, total=GRID_COLUMNS, x0=0):
    """Divide the grid into n equal columns; returns [(x, width), ...]."""
    if n < 1:
        return []
    w = total // n
    return [(x0 + i * w, w) for i in range(n)]


class RefSeq:
    """Unique widget reference strings (svggraph and pie require one)."""

    def __init__(self, prefix="NG"):
        """Start an endless supply of reference strings, each the prefix
        followed by three letters (NGAAA, NGAAB, ...)."""
        self._it = (prefix + a + b + c
                    for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    def __iter__(self):
        """RefSeq is its own iterator so next(refseq) works."""
        return self

    def __next__(self):
        """Return the next unique reference string in the sequence."""
        return next(self._it)

    def next(self):
        """Backward-compatible alias for next(self)."""
        return next(self._it)


class Api:
    """Minimal Zabbix JSON-RPC client. Token from env ZTOKEN only."""

    def __init__(self, url, timeout=20):
        """Prepare a Zabbix API client for the given URL, taking the auth
        token from the ZTOKEN environment variable (never from argv) and
        raising ZabbixError if it is unset."""
        if not url.endswith(".php"):
            url = url.rstrip("/") + "/api_jsonrpc.php"
        self.url = url
        self.timeout = timeout
        token = os.environ.get("ZTOKEN")
        if not token:
            raise ZabbixError(
                "ZTOKEN is not set in the environment; export the API token "
                "as ZTOKEN (never pass it on the command line)")
        self._token = token
        self._id = itertools.count(1)

    def call(self, method, params):
        """Issue one JSON-RPC request and return its result. Connection,
        HTTP, non-JSON, and API-level errors are all raised as ZabbixError
        with a clear message and no token leaked."""
        body = json.dumps({
            "jsonrpc": "2.0", "method": method,
            "params": params, "id": next(self._id),
        }).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json-rpc",
                     "Authorization": "Bearer %s" % self._token})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise ZabbixError("cannot reach Zabbix API at %s: HTTP %s %s"
                              % (self.url, e.code, e.reason))
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise ZabbixError("cannot reach Zabbix API at %s: %s"
                              % (self.url, reason))
        try:
            r = json.loads(raw)
        except ValueError:
            raise ZabbixError("non-JSON response from %s to %s"
                              % (self.url, method))
        if "error" in r:
            err = r["error"]
            raise ZabbixError("%s failed: %s %s" % (
                method, err.get("message", ""), err.get("data", "")))
        return r["result"]


def resolve_group(api, group_name):
    """Host group name to (groupid, [{hostid, host, name}, ...]).

    The group is the canonical fleet definition: onboarding a host is
    linking the template and adding it to this group, then re-running the
    generator.
    """
    groups = api.call("hostgroup.get", {
        "filter": {"name": [group_name]},
        "output": ["groupid", "name"]})
    if not groups:
        raise ZabbixError("host group not found: %s" % group_name)
    gid = groups[0]["groupid"]
    hosts = api.call("host.get", {
        "groupids": [gid],
        "output": ["hostid", "host", "name"],
        "sortfield": "host"})
    if not hosts:
        raise ZabbixError("host group %s has no members" % group_name)
    return gid, hosts


def resolve_items(api, hostid):
    """All nodeguard items on one host, as {key: {itemid, value_type, units}}.

    The value type decides how a tile renders: an unsigned counter wants no
    decimal places, a text item wants a smaller value font than a number so
    it is not clipped, and a unixtime item renders as a full datetime that
    needs a wide tile. Resolving ids alone forced every tile to share one
    presentation, which is how integer counters came to read "1691.00" in a
    tile too narrow to show the "1691".
    """
    out = {}
    for it in api.call("item.get", {
            "hostids": [hostid],
            "search": {"key_": "nodeguard."},
            "output": ["itemid", "key_", "name", "value_type", "units",
                       "lastvalue"]}):
        out[it["key_"]] = {"itemid": it["itemid"],
                           "value_type": int(it["value_type"]),
                           "units": it.get("units", ""),
                           "name": it["name"],
                           "lastvalue": it.get("lastvalue", "")}
    return out


# Zabbix item value types.
VT_FLOAT = 0
VT_CHAR = 1
VT_LOG = 2
VT_UNSIGNED = 3
VT_TEXT = 4
VT_NUMERIC = (VT_FLOAT, VT_UNSIGNED)


def resolve_itemids(api, hostid):
    """All nodeguard item keys on one host, as {key: itemid}."""
    return {k: v["itemid"] for k, v in resolve_items(api, hostid).items()}


def _f(ftype, name, value):
    """Build one Zabbix widget field dict (type, name, stringified value)."""
    return {"type": ftype, "name": name, "value": str(value)}


def widget(wtype, x, y, w, h, name="", fields=None):
    """Assemble a generic dashboard widget dict at a grid position; the
    typed builders below wrap this with their own field lists."""
    return {"type": wtype, "name": name, "x": x, "y": y,
            "width": w, "height": h, "fields": fields or []}


def itemvalue(x, y, w, h, name, itemid, thresholds=(), sparkline=False,
              description="", decimals=None, value_size=None,
              desc_size=DESC_SIZE, sparkline_from="now-3h", bg_color=""):
    """Single item value tile (widget type "item").

    name is the widget header and carries the METRIC only. The host goes in
    description, which gets the tile's full width; putting it in the header
    instead spends the whole header budget before the metric is named (see
    the legibility note above HEADER_GUTTER_PX).

    thresholds is [(value, hex), ...] and colors the value at or above each
    entry, leaving anything below the lowest entry uncolored; include an
    entry at "0" so a healthy zero and a broken zero do not both render as
    plain white. decimals sets decimal_places (0 for counters). value_size
    must suit the tile height and the widest string the item can hold.
    sparkline draws the recent trend behind the number.
    """
    fl = [_f(FIELD_ITEM, "itemid", itemid)]
    shown = ([SHOW_DESCRIPTION] if description else []) + [SHOW_VALUE]
    if sparkline:
        shown.append(SHOW_SPARKLINE)
    for i, what in enumerate(shown):
        fl.append(_f(FIELD_INT, "show.%d" % i, what))
    if description:
        fl += [_f(FIELD_STR, "description", description),
               _f(FIELD_INT, "desc_size", desc_size),
               _f(FIELD_INT, "desc_v_pos", 0),
               _f(FIELD_INT, "desc_h_pos", 1)]
    if bg_color:
        fl.append(_f(FIELD_STR, "bg_color", bg_color))
    if decimals is not None:
        fl.append(_f(FIELD_INT, "decimal_places", decimals))
    if value_size is not None:
        fl.append(_f(FIELD_INT, "value_size", value_size))
    for i, (val, color) in enumerate(thresholds):
        fl += [_f(FIELD_STR, "thresholds.%d.color" % i, color),
               _f(FIELD_STR, "thresholds.%d.threshold" % i, str(val))]
    if sparkline:
        fl += [_f(FIELD_STR, "sparkline.color", "3388CC"),
               _f(FIELD_INT, "sparkline.time_period.from_type", 0),
               _f(FIELD_STR, "sparkline.time_period.from", sparkline_from)]
    return widget("item", x, y, w, h, name, fl)


def gauge(x, y, w, h, name, itemid, vmin=0, vmax=100, thresholds=(),
          description="", desc_size=DESC_SIZE, decimals=0, value_size=28):
    """Gauge widget; thresholds is [(value, color_hex), ...].

    description defaults in Zabbix to "{ITEM.NAME}", which renders the full
    item name in oversized text under the dial and is clipped at any width
    this dashboard uses; pass the host name instead, or "" for nothing. The
    threshold arc and its labels are turned on because a dial whose needle
    sits near zero otherwise says nothing about how far the value is from
    the thresholds that matter.
    """
    fl = [_f(FIELD_ITEM, "itemid", itemid),
          _f(FIELD_STR, "min", vmin),
          _f(FIELD_STR, "max", vmax),
          _f(FIELD_STR, "description", description),
          _f(FIELD_INT, "desc_size", desc_size),
          _f(FIELD_INT, "desc_v_pos", 0),
          _f(FIELD_INT, "decimal_places", decimals),
          _f(FIELD_INT, "value_size", value_size)]
    if thresholds:
        fl += [_f(FIELD_INT, "th_show_arc", 1),
               _f(FIELD_INT, "th_arc_size", 12),
               _f(FIELD_INT, "th_show_labels", 1)]
    for i, (val, color) in enumerate(thresholds):
        fl += [_f(FIELD_STR, "thresholds.%d.color" % i, color),
               _f(FIELD_STR, "thresholds.%d.threshold" % i, val)]
    return widget("gauge", x, y, w, h, name, fl)


def svggraph(x, y, w, h, name, datasets, refseq, stacked=False,
             legend_lines=4, legend_columns=1):
    """SVG graph. datasets is [(host_patterns, item_patterns, color), ...].

    host_patterns and item_patterns may each be a string or a list; host
    patterns match the Zabbix VISIBLE host name (API search on "name"),
    and items are addressed by display-NAME pattern per the template's
    display-name contract, so a rename would empty the graph (guarded by
    check_template.py).

    The legend defaults to one column of variable height. Zabbix's own
    default is four columns, which on a half-width graph gives each series
    about 170px and rendered every entry as "<host>: nodegua..." -- four
    indistinguishable series on the drop-rate graph, where telling v4 from
    v6 and home from office is the entire point.
    """
    fl = [_f(FIELD_STR, "reference", next(refseq))]
    for i, (hosts, items, color) in enumerate(datasets):
        hosts = [hosts] if isinstance(hosts, str) else list(hosts)
        items = [items] if isinstance(items, str) else list(items)
        for j, hp in enumerate(hosts):
            fl.append(_f(FIELD_STR, "ds.%d.hosts.%d" % (i, j), hp))
        for j, ip in enumerate(items):
            fl.append(_f(FIELD_STR, "ds.%d.items.%d" % (i, j), ip))
        fl.append(_f(FIELD_STR, "ds.%d.color" % i, color))
        if stacked:
            fl.append(_f(FIELD_INT, "ds.%d.stacked" % i, 1))
    fl += [_f(FIELD_INT, "legend_lines", legend_lines),
           _f(FIELD_INT, "legend_columns", legend_columns),
           _f(FIELD_INT, "legend_lines_mode", 1)]
    return widget("svggraph", x, y, w, h, name, fl)


def pie(x, y, w, h, name, host_pattern, item_patterns):
    """Pie chart: one dataset of item name patterns on one host pattern.
    The host pattern matches the Zabbix VISIBLE host name.
    NOTE: field set verified against a hand-built 7.4 widget export
    (2026-09-05): piechart takes NO reference field and NO per-item color
    list; colors come from ds.N.color_palette (INT). Sending reference or
    ds.N.color.N leaves the widget spinning forever and crashes its edit
    dialog."""
    fl = [_f(FIELD_STR, "ds.0.hosts.0", host_pattern),
          _f(FIELD_INT, "ds.0.color_palette", 0)]
    for j, ip in enumerate(item_patterns):
        fl.append(_f(FIELD_STR, "ds.0.items.%d" % j, ip))
    return widget("piechart", x, y, w, h, name, fl)


def honeycomb(x, y, w, h, name, item_pattern, thresholds=(),
              groupid=None, hostid=None, primary_label="{ITEM.NAME}",
              primary_label_size=11, secondary_label_size=22):
    """Honeycomb addressed by host GROUP or by one host, plus an item
    name pattern. thresholds is [(value, color_hex), ...].

    primary_label defaults to the ITEM name because the cells are the thing
    being distinguished. Labelling them "{HOST.NAME}" instead, as this
    module did until 2026-09-20, produced six cells reading "gateway-home"
    and "gateway-office" over a per-feed age: three of them amber or red,
    and no way to tell which feed had gone stale. Scope a honeycomb to one
    host and put the host in the widget header to keep both facts.

    Group addressing still means a new group member appears with no widget
    rework; per-host honeycombs are generated from live group membership
    and so cost no edit either.
    """
    fl = [_f(FIELD_STR, "items.0", item_pattern),
          _f(FIELD_INT, "primary_label_type", 0),
          _f(FIELD_STR, "primary_label", primary_label),
          _f(FIELD_INT, "primary_label_size_type", 1),
          _f(FIELD_INT, "primary_label_size", primary_label_size),
          _f(FIELD_INT, "secondary_label_type", 1),
          _f(FIELD_INT, "secondary_label_size_type", 1),
          _f(FIELD_INT, "secondary_label_size", secondary_label_size),
          _f(FIELD_INT, "secondary_label_bold", 1)]
    if hostid is not None:
        fl.append(_f(FIELD_HOST, "hostids.0", hostid))
    elif groupid is not None:
        fl.append(_f(FIELD_GROUP, "groupids.0", groupid))
    else:
        raise ValueError("honeycomb needs a groupid or a hostid")
    for i, (val, color) in enumerate(thresholds):
        fl += [_f(FIELD_STR, "thresholds.%d.color" % i, color),
               _f(FIELD_STR, "thresholds.%d.threshold" % i, val)]
    return widget("honeycomb", x, y, w, h, name, fl)


def url_widget(x, y, w, h, name, url):
    """Legend URL widget. The Zabbix URL widget refuses data: URIs, so the
    text cannot be inlined here; it is served same-origin by the frontend
    from the zabbix-dashboard-notes ConfigMap instead. Same-origin also
    avoids depending on a third party sending no frame-blocking headers.
    The iframe carries sandbox="" (no allow-scripts), so that page must
    work without JavaScript."""
    return widget("url", x, y, w, h, name, [_f(FIELD_STR, "url", url)])
