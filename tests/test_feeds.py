#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for bin/nodeguard-feeds: the Spamhaus and DShield parsers
driven with hostile and truncated bodies, the run-level containment that
keeps one bad body from killing the run (evaluation finding S4), and the
feed gates."""

import ipaddress
import json
import os
import unittest

import ngtest

ngmap = ngtest.load_bin("ngmap", "ngmap.py")
feeds = ngtest.load_bin("nodeguard_feeds", "nodeguard-feeds")

SPAMHAUS_CIDR = "203.0.113.0/24"
CONTAINED_HOST = "203.0.113.7/32"
DSHIELD_ROW = "198.51.100.0\t198.51.100.255\t24\t3\tExample"
SPAMHAUS = "spamhaus_drop_v4"
DSHIELD = "dshield_top20"
BOOT_ID = "00000000-0000-4000-8000-000000000001"
ALLOW_NET = "192.0.2.0/24"


def jsonl(*objects):
    """Render objects as a JSONL body, the shape Spamhaus DROP ships."""
    return ("\n".join(json.dumps(o) for o in objects) + "\n").encode()


def spamhaus_body(records=None, cidr=SPAMHAUS_CIDR, count=1, trailer=True,
                  trailer_last=True):
    """Build a Spamhaus DROP body; every argument names one way a real
    body can be wrong."""
    rows = records if records is not None else [{"cidr": cidr,
                                                 "sblid": "SBL1"}]
    meta = {"type": "metadata", "records": count, "copyright": "(c) test",
            "timestamp": 1}
    if not trailer:
        return jsonl(*rows)
    return jsonl(*([meta] + rows if not trailer_last else rows + [meta]))


class SpamhausParserTest(unittest.TestCase):
    """Bodies that must parse, and bodies that must be refused."""

    def test_valid_body_parses(self):
        records, attribution = feeds.parse_spamhaus(spamhaus_body())
        self.assertEqual(records,
                         [(ipaddress.ip_network(SPAMHAUS_CIDR), "SBL1")])
        self.assertEqual(attribution["copyright"], "(c) test")

    def test_valid_multi_record_body_parses(self):
        rows = [{"cidr": "203.0.113.0/24"}, {"cidr": "192.0.2.0/24"}]
        records, _ = feeds.parse_spamhaus(spamhaus_body(records=rows,
                                                        count=2))
        self.assertEqual(len(records), 2)


class SpamhausRegressionTest(unittest.TestCase):
    """Finding S4, failing-first: bodies a remote party can send that the
    parser accepted or crashed on before this change. The records cases
    raised TypeError past the per-feed handler; the cidr cases were
    silently accepted as bogus /32 networks."""

    def assert_refused(self, body):
        """The parser must refuse the body as a validation failure, which
        is the exception class the per-feed handler contains."""
        with self.assertRaises(ValueError):
            feeds.parse_spamhaus(body)

    def test_records_as_list_is_refused(self):
        self.assert_refused(spamhaus_body(count=[]))

    def test_records_as_null_is_refused(self):
        self.assert_refused(spamhaus_body(count=None))

    def test_records_as_object_is_refused(self):
        self.assert_refused(spamhaus_body(count={}))

    def test_records_as_boolean_is_refused(self):
        self.assert_refused(spamhaus_body(count=True))

    def test_records_as_numeric_string_is_refused(self):
        self.assert_refused(spamhaus_body(count="1"))

    def test_cidr_as_integer_is_refused(self):
        self.assert_refused(spamhaus_body(cidr=123))

    def test_cidr_as_boolean_is_refused(self):
        self.assert_refused(spamhaus_body(cidr=True))


class SpamhausPinnedBehaviorTest(unittest.TestCase):
    """Bodies already refused before this change; pinned so the S4 fix
    cannot loosen them."""

    def assert_refused(self, body):
        with self.assertRaises(ValueError):
            feeds.parse_spamhaus(body)

    def test_records_as_non_numeric_string_is_refused(self):
        self.assert_refused(spamhaus_body(count="many"))

    def test_cidr_as_list_is_refused(self):
        self.assert_refused(spamhaus_body(cidr=[]))

    def test_cidr_as_object_is_refused(self):
        self.assert_refused(spamhaus_body(cidr={}))

    def test_cidr_as_null_is_refused(self):
        self.assert_refused(spamhaus_body(cidr=None))

    def test_missing_trailer_is_refused(self):
        self.assert_refused(spamhaus_body(trailer=False))

    def test_trailer_not_final_line_is_refused(self):
        self.assert_refused(spamhaus_body(trailer_last=False))

    def test_truncated_body_is_refused(self):
        rows = [{"cidr": "203.0.113.0/24"}]
        self.assert_refused(spamhaus_body(records=rows, count=2))

    def test_non_object_line_is_refused(self):
        self.assert_refused(jsonl(["not", "an", "object"]))

    def test_cidr_less_record_is_refused(self):
        self.assert_refused(spamhaus_body(records=[{"sblid": "SBL1"}]))

    def test_undecodable_body_is_refused(self):
        with self.assertRaises(UnicodeDecodeError):
            feeds.parse_spamhaus(b"\xff\xfe not utf-8\n")

    def test_non_json_line_is_refused(self):
        with self.assertRaises(json.JSONDecodeError):
            feeds.parse_spamhaus(b"this is not json\n")


class DShieldParserTest(unittest.TestCase):
    """The DShield block list's row grammar."""

    def test_valid_body_parses(self):
        body = ("# comment header\n" + DSHIELD_ROW + "\n").encode()
        records, attribution = feeds.parse_dshield(body)
        self.assertEqual(
            records, [(ipaddress.ip_network("198.51.100.0/24"), "Example")])
        self.assertEqual(attribution, {})

    def test_too_few_columns_is_refused(self):
        with self.assertRaises(ValueError):
            feeds.parse_dshield(b"198.51.100.0\t198.51.100.255\n")

    def test_non_24_mask_is_refused(self):
        with self.assertRaises(ValueError):
            feeds.parse_dshield(b"198.51.100.0\t198.51.100.255\t16\n")

    def test_end_not_the_broadcast_is_refused(self):
        with self.assertRaises(ValueError):
            feeds.parse_dshield(b"198.51.100.0\t198.51.100.9\t24\n")

    def test_non_network_start_address_is_refused(self):
        with self.assertRaises(ValueError):
            feeds.parse_dshield(b"198.51.100.9\t198.51.100.255\t24\n")


class RunnerFixture(unittest.TestCase):
    """A Runner with every path, transport, and map boundary faked: state
    under a temporary directory, canned fetch responses, and the in-memory
    maps. No network, no bpftool, no host state."""

    def setUp(self):
        self.tmp = ngtest.temp_dir(self)
        state_dir = os.path.join(self.tmp, "feeds")
        boot_path = os.path.join(self.tmp, "boot_id")
        with open(boot_path, "w") as f:
            f.write(BOOT_ID + "\n")
        # The derived path constants are evaluated at import, so each one
        # is redirected individually rather than through STATE_DIR.
        ngtest.patch_attrs(self, feeds,
                           CONF=os.path.join(self.tmp, "feeds.conf"),
                           ENV=os.path.join(self.tmp, "nodeguard.env"),
                           STATE_DIR=state_dir,
                           STATE=f"{state_dir}/state.json",
                           APPROVED=f"{state_dir}/approved.json",
                           KV=f"{state_dir}/feeds.kv",
                           DIFF=f"{state_dir}/last-diff.txt",
                           BOOT_ID_PATH=boot_path,
                           fetch=self.fake_fetch)
        self.fake = ngtest.FakeMaps(allow=[ipaddress.ip_network(ALLOW_NET)])
        self.fake.install(self, ngmap)
        self.responses = {}

    def fake_fetch(self, feed, _meta, _max_bytes):
        """Stand in for the HTTP transport; no request is ever built."""
        return self.responses.get(feed, ("failed:no fixture", None, {}))

    def conf(self, **over):
        """Config for a run over the two v4 feeds, with the record-count
        floors lowered so a fixture body of one row is legal."""
        conf = dict(feeds.DEFAULTS)
        conf["FEEDS_DRYRUN"] = f"{SPAMHAUS} {DSHIELD}"
        conf[f"FEEDS_MIN_{SPAMHAUS.upper()}"] = "1"
        conf[f"FEEDS_MIN_{DSHIELD.upper()}"] = "1"
        conf.update(over)
        return conf

    def enforcing_conf(self, **over):
        """Config whose feeds clear the full double gate, so a run really
        writes to the maps."""
        feeds.save_json(feeds.APPROVED, {"feeds": [SPAMHAUS, DSHIELD]})
        return self.conf(FEEDS_ENFORCE="yes",
                         FEEDS_APPLY=f"{SPAMHAUS} {DSHIELD}",
                         FEEDS_DRYRUN="", **over)

    def serve(self, spamhaus_ok=True, dshield_ok=True, **body_args):
        """Arm the canned fetch responses for both feeds."""
        body = (spamhaus_body(**body_args) if spamhaus_ok
                else spamhaus_body(count=[]))
        self.responses[SPAMHAUS] = ("ok", body, {})
        self.responses[DSHIELD] = (
            "ok", ("# header\n" + DSHIELD_ROW + "\n").encode(), {})
        if not dshield_ok:
            self.responses[DSHIELD] = ("failed:HTTP 503", None, {})

    def state_on_disk(self):
        """Read back the persisted state file."""
        with open(feeds.STATE) as f:
            return json.load(f)

    def diff_on_disk(self):
        """Read back the persisted run diff."""
        with open(feeds.DIFF) as f:
            return f.read()

    def kv_on_disk(self):
        """Read back the persisted metrics kv as a dict; this is the half
        of end-of-run reporting the monitoring alarms on."""
        with open(feeds.KV) as f:
            return dict(ln.split("=", 1) for ln in f.read().splitlines() if ln)


class RunContainmentTest(RunnerFixture):
    """Finding S4 at the run level: a hostile body costs its own feed, and
    an unexpected crash never arms crash-adoption from remote content."""

    def test_hostile_body_fails_only_its_feed(self):
        self.serve(spamhaus_ok=False)
        with ngtest.captured_log() as log:
            rc = feeds.Runner(self.conf()).run()
        self.assertEqual(rc, 1)
        diff = self.diff_on_disk()
        self.assertIn(f"FAILED {SPAMHAUS}: validation:", diff)
        self.assertIn(f"SUMMARY {DSHIELD}: dry-run", log.getvalue())
        self.assertFalse(self.state_on_disk()["run_in_progress"])
        self.assertTrue(
            os.path.exists(f"{feeds.STATE_DIR}/{SPAMHAUS}/last-bad"))

    def test_unanticipated_parser_exception_is_contained(self):
        def explode(_body):
            raise TypeError("parser surprise")

        parsers = dict(feeds.PARSERS)
        parsers["spamhaus"] = explode
        ngtest.patch_attrs(self, feeds, PARSERS=parsers)
        self.serve()
        with ngtest.captured_log() as log:
            rc = feeds.Runner(self.conf()).run()
        self.assertEqual(rc, 1)
        self.assertIn(f"FAILED {SPAMHAUS}: validation: TypeError",
                      self.diff_on_disk())
        self.assertIn(f"SUMMARY {DSHIELD}: dry-run", log.getvalue())
        self.assertFalse(self.state_on_disk()["run_in_progress"])

    def test_unexpected_exception_with_no_writes_clears_the_marker(self):
        self.serve()
        runner = feeds.Runner(self.conf())

        def explode(_per_feed, _allow):
            raise RuntimeError("injected failure before any write")

        runner.gate = explode
        with ngtest.captured_log():
            with self.assertRaises(RuntimeError):
                runner.run()
        self.assertEqual(runner.writes, 0)
        self.assertFalse(self.state_on_disk()["run_in_progress"])
        # The crash must still alarm: clearing the marker cannot be paid
        # for by a silent run, so the diff and the metrics both land.
        self.assertTrue(os.path.exists(feeds.DIFF))
        self.assertEqual(self.kv_on_disk()["ng.feeds_failed"], "2")
        with ngtest.captured_log() as log:
            nxt = feeds.Runner(self.conf())
        self.assertFalse(nxt.adoption)
        self.assertNotIn("adoption mode", log.getvalue())

    def test_unexpected_exception_after_a_write_keeps_the_marker(self):
        conf = self.enforcing_conf()
        self.serve()
        # Crash-adoption is same-boot recovery, so the state has to carry
        # a boot id already; one clean run puts it there.
        with ngtest.captured_log():
            feeds.Runner(conf).run()
        runner = feeds.Runner(conf)
        real_reconcile = runner.reconcile
        seen = []

        def flaky(feed, desired, enforce):
            # The first feed reconciles for real, so the writes counter is
            # driven by the shipped code path, not by the test.
            seen.append(feed)
            if len(seen) == 1:
                return real_reconcile(feed, desired, enforce)
            raise RuntimeError("injected failure after a write")

        runner.reconcile = flaky
        with ngtest.captured_log():
            with self.assertRaises(RuntimeError):
                runner.run()
        self.assertGreater(runner.writes, 0)
        self.assertNotEqual(self.fake.updates, [])
        self.assertTrue(self.state_on_disk()["run_in_progress"])
        self.assertEqual(self.kv_on_disk()["ng.feeds_failed"], "2")
        with ngtest.captured_log() as log:
            nxt = feeds.Runner(conf)
        self.assertTrue(nxt.adoption)
        self.assertIn("adoption mode", log.getvalue())


class ContainedCorpseTest(RunnerFixture):
    """Finding K2 on the bulk path: a CIDR the loader inserts clears the
    expired host routes it now covers, which the kernel's single LPM
    lookup would otherwise let pass inside the live CIDR."""

    def block4(self):
        """The v4 block map path the fixture's feeds write to."""
        return f"{ngmap.PIN}/block4"

    def put(self, cidr, expiry):
        """Put one block entry in the fake map and return its network."""
        net = ipaddress.ip_network(cidr)
        self.fake.update_map(self.block4(), ngmap.key_bytes(net),
                             feeds.encode_value(expiry, 0))
        return net

    def present(self, net):
        """Whether the fake block map still holds an entry."""
        return self.fake.lookup_value(
            self.block4(), ngmap.key_bytes(net)) is not None

    def test_insert_deletes_a_contained_corpse(self):
        corpse = self.put(CONTAINED_HOST, expiry=1)
        self.serve()
        with ngtest.captured_log():
            feeds.Runner(self.enforcing_conf()).run()
        self.assertTrue(self.present(ipaddress.ip_network(SPAMHAUS_CIDR)))
        self.assertFalse(self.present(corpse))

    def test_insert_keeps_a_contained_live_entry(self):
        live = self.put(CONTAINED_HOST, expiry=ngmap.mono_ns() + 10 ** 12)
        self.serve()
        with ngtest.captured_log():
            feeds.Runner(self.enforcing_conf()).run()
        self.assertTrue(self.present(live))

    def test_a_corpse_arising_after_the_snapshot_waits_for_the_sweep(self):
        # The snapshot bounds the candidates, so an entry that expires
        # mid-run is not the insert path's to delete.
        self.serve()
        runner = feeds.Runner(self.enforcing_conf())
        real_snapshot = runner.snapshot_expired

        def snapshot_then_add_a_corpse():
            snap = real_snapshot()
            self.put(CONTAINED_HOST, expiry=1)
            return snap

        runner.snapshot_expired = snapshot_then_add_a_corpse
        with ngtest.captured_log():
            runner.run()
        self.assertTrue(self.present(ipaddress.ip_network(CONTAINED_HOST)))

    def test_a_corpse_this_loader_still_owns_is_not_a_candidate(self):
        # Deleting another feed's own expired key would make that feed's
        # reconcile log the foreign-interference warning against itself.
        corpse = self.put(CONTAINED_HOST, expiry=1)
        feeds.save_json(feeds.STATE, {"entries": {
            feeds.jkey(corpse): {"feed": DSHIELD, "ref": "row",
                                 "written_expiry_ns": 1,
                                 "first_seen": 1.0, "last_written": 1.0}}})
        runner = feeds.Runner(self.enforcing_conf())
        self.assertEqual(runner.snapshot_expired()[self.block4()], [])


class GateTest(RunnerFixture):
    """The run-level content gates, driven directly with crafted desired
    sets rather than through a fetch."""

    def runner(self, **over):
        """A Runner over the fixture's faked state, ready for gate()."""
        with ngtest.captured_log():
            return feeds.Runner(self.conf(**over))

    def test_canary_coverage_fails_the_whole_feed(self):
        runner = self.runner()
        runner.canary = "203.0.113.5"
        per_feed = {SPAMHAUS: [(ipaddress.ip_network(SPAMHAUS_CIDR), "r")]}
        runner.gate(per_feed, [])
        self.assertNotIn(SPAMHAUS, per_feed)
        self.assertIn(SPAMHAUS, runner.failed)
        self.assertIn("covers the canary", "\n".join(runner.diff_lines))

    def test_entry_cap_aborts_the_run(self):
        runner = self.runner(FEEDS_MAX_V4="1")
        per_feed = {SPAMHAUS: [(ipaddress.ip_network(SPAMHAUS_CIDR), "r"),
                               (ipaddress.ip_network("198.51.100.0/24"), "r")]}
        with self.assertRaises(feeds.GateAbort):
            runner.gate(per_feed, [])

    def test_coverage_cap_aborts_the_run(self):
        runner = self.runner(FEEDS_MAX_COVERAGE_V4="100")
        per_feed = {SPAMHAUS: [(ipaddress.ip_network(SPAMHAUS_CIDR), "r")]}
        with self.assertRaises(feeds.GateAbort):
            runner.gate(per_feed, [])

    def test_protected_entry_is_rejected_per_entry(self):
        runner = self.runner()
        per_feed = {SPAMHAUS: [(ipaddress.ip_network("10.1.2.0/24"), "r"),
                               (ipaddress.ip_network(SPAMHAUS_CIDR), "r")]}
        runner.gate(per_feed, [])
        self.assertEqual(list(per_feed[SPAMHAUS]), [SPAMHAUS_CIDR])
        self.assertEqual(runner.rejected, 1)

    def test_allowlisted_entry_is_rejected_per_entry(self):
        runner = self.runner()
        allow = [ipaddress.ip_network(ALLOW_NET)]
        per_feed = {SPAMHAUS: [(ipaddress.ip_network(ALLOW_NET), "r")]}
        runner.gate(per_feed, allow)
        self.assertEqual(per_feed[SPAMHAUS], {})
        self.assertEqual(runner.rejected, 1)

    def test_cross_feed_dedupe_gives_the_key_to_the_first_feed(self):
        runner = self.runner()
        net = ipaddress.ip_network(SPAMHAUS_CIDR)
        per_feed = {SPAMHAUS: [(net, "first")], DSHIELD: [(net, "second")]}
        runner.gate(per_feed, [])
        self.assertEqual(list(per_feed[SPAMHAUS]), [SPAMHAUS_CIDR])
        self.assertEqual(per_feed[DSHIELD], {})

    def churn_runner(self, **conf):
        """A Runner with Spamhaus enforcing and a 10-entry applied baseline."""
        runner = self.runner(**dict({"FEEDS_ENFORCE": "yes",
                                     "FEEDS_APPLY": SPAMHAUS}, **conf))
        runner.approved = {"feeds": [SPAMHAUS]}
        runner.feed_meta(SPAMHAUS)["applied_cidrs"] = [
            f"203.0.113.{n}/32" for n in range(10)]
        return runner

    def wholly_replaced(self):
        """A desired set sharing no key with the baseline. Note this is 200
        percent churn, not 100: the metric is the symmetric difference over
        the baseline size, so every key removed AND every key added counts."""
        return {SPAMHAUS: [(ipaddress.ip_network(f"198.51.100.{n}/32"), "r")
                           for n in range(10)]}

    def rotated(self, n):
        """Baseline keys with n of the 10 swapped for new ones, which is the
        shape of a real daily rotation: churn is 2n over 10."""
        keep = [f"203.0.113.{i}/32" for i in range(n, 10)]
        fresh = [f"198.51.100.{i}/32" for i in range(n)]
        return {SPAMHAUS: [(ipaddress.ip_network(c), "r")
                           for c in keep + fresh]}

    def test_per_feed_override_lets_a_rotating_feed_through(self):
        """dshield_top20 moves 13 of 19 entries daily, which is 137 percent by
        this metric. A feed given a threshold above its normal movement must
        not be held where the global default holds it."""
        # 7 of 10 swapped is 14 over 10, or 140 percent by this metric.
        default_run = self.churn_runner()
        default_run.gate(self.rotated(7), [])
        self.assertIn(SPAMHAUS, default_run.churn_held)

        tuned = self.churn_runner(
            **{f"FEEDS_MAX_CHURN_PCT_{SPAMHAUS.upper()}": "150"})
        tuned.gate(self.rotated(7), [])
        self.assertNotIn(SPAMHAUS, tuned.churn_held)

    def test_absent_override_still_uses_the_global_default(self):
        """The default path is untouched: no override means the old behaviour."""
        runner = self.churn_runner()
        runner.gate(self.wholly_replaced(), [])
        self.assertIn(SPAMHAUS, runner.churn_held)

    def test_override_applies_only_to_its_own_feed(self):
        """A threshold on one feed must not raise another feed's."""
        runner = self.churn_runner(
            **{f"FEEDS_MAX_CHURN_PCT_{DSHIELD.upper()}": "100"})
        runner.gate(self.wholly_replaced(), [])
        self.assertIn(SPAMHAUS, runner.churn_held)

    def test_malformed_override_fails_the_run(self):
        """A typo must not silently fall back to the default."""
        runner = self.churn_runner(
            **{f"FEEDS_MAX_CHURN_PCT_{SPAMHAUS.upper()}": "thirty"})
        with self.assertRaises(ValueError):
            runner.gate(self.wholly_replaced(), [])

    def test_hold_record_names_the_applied_threshold(self):
        """An operator must be able to tell a tuned feed that still moved too
        far from one that was never tuned."""
        runner = self.churn_runner(
            **{f"FEEDS_MAX_CHURN_PCT_{SPAMHAUS.upper()}": "40"})
        runner.gate(self.wholly_replaced(), [])
        self.assertIn(SPAMHAUS, runner.churn_held)
        self.assertIn("exceeds 40 percent", "\n".join(runner.diff_lines))

    def test_churn_brake_holds_a_diverging_feed(self):
        runner = self.runner(**{"FEEDS_ENFORCE": "yes",
                                "FEEDS_APPLY": SPAMHAUS})
        runner.approved = {"feeds": [SPAMHAUS]}
        base = [f"203.0.113.{n}/32" for n in range(10)]
        runner.feed_meta(SPAMHAUS)["applied_cidrs"] = base
        per_feed = {SPAMHAUS: [(ipaddress.ip_network(f"198.51.100.{n}/32"),
                                "r") for n in range(10)]}
        runner.gate(per_feed, [])
        self.assertIn(SPAMHAUS, runner.churn_held)
        self.assertIn("CHURN-HELD", "\n".join(runner.diff_lines))


class ReconcilePlanTest(RunnerFixture):
    """What reconcile plans when a feed is held or failed. Planning is
    asserted in dry-run, where the plan is the whole output."""

    def runner_with_owned_entry(self):
        """A Runner owning one entry for the Spamhaus feed."""
        with ngtest.captured_log():
            runner = feeds.Runner(self.conf())
        runner.state["entries"] = {
            SPAMHAUS_CIDR: {"feed": SPAMHAUS, "ref": "r",
                            "written_expiry_ns": 1, "first_seen": 0,
                            "last_written": 0}}
        return runner

    def test_owned_entry_not_desired_is_withdrawn(self):
        runner = self.runner_with_owned_entry()
        counts = runner.reconcile(SPAMHAUS, {}, enforce=False)
        self.assertEqual(counts["withdraw"], 1)

    def test_failed_feed_plans_no_withdrawal(self):
        # INVARIANT W1: a feed that failed this run withdraws nothing; its
        # entries age out by TTL instead.
        runner = self.runner_with_owned_entry()
        runner.failed.append(SPAMHAUS)
        counts = runner.reconcile(SPAMHAUS, {}, enforce=False)
        self.assertEqual(counts["withdraw"], 0)

    def test_churn_held_feed_plans_no_insert_or_withdrawal(self):
        runner = self.runner_with_owned_entry()
        runner.churn_held.append(SPAMHAUS)
        net = ipaddress.ip_network("198.51.100.0/24")
        counts = runner.reconcile(SPAMHAUS, {str(net): (net, "r")},
                                  enforce=False)
        self.assertEqual(counts["insert"], 0)
        self.assertEqual(counts["withdraw"], 0)


if __name__ == "__main__":
    unittest.main()
