#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for bin/nodeguard-responder: the seven gates in their
documented order, TTL escalation, the rate caps, the journal's
durability rules, and the kv heartbeat and alert-lag telemetry that make
a wedged responder visible. Every event is driven through handle_event,
so no daemon, no eve.json tail, and no subprocess is involved."""

import datetime
import ipaddress
import json
import os
import time
import unittest

import ngtest

responder = ngtest.load_bin("nodeguard_responder", "nodeguard-responder")

# NOTE: the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) all report is_global False, so the direction gate
# refuses them before any later gate runs. An attacker fixture therefore
# has to be a globally routable address; these two belong to no system
# this repository touches, and only the local half of each event uses a
# documentation range.
ATTACKER = "1.2.3.4"
ATTACKER_2 = "1.2.3.5"
TARGET = "192.0.2.10"
HOME_NET = "192.0.2.0/24"
SID = 1000
TTL_BASE = 3600
TTL_MAX = 86400
BOOT_ID = "00000000-0000-4000-8000-000000000001"
OTHER_BOOT_ID = "00000000-0000-4000-8000-000000000002"
# A whole-second processing moment for the lag arithmetic: a fractional
# one makes the microsecond round trip through the ISO 8601 stamp land
# either side of the integer boundary, which would flake.
NOW = 1788645600.0


def alert(**over):
    """One eve.json alert line that passes every gate unless overridden."""
    event = {"event_type": "alert", "src_ip": ATTACKER, "dest_ip": TARGET,
             "proto": "TCP",
             "alert": {"signature_id": SID, "severity": 1,
                       "signature": "ET TEST"},
             "flow": {"pkts_toclient": 2, "pkts_toserver": 3}}
    event.update(over)
    return json.dumps(event)


class FakeAllow:
    """Stub allow provider: True protected, False blockable, None
    undeterminable (the contract handle_event must fail safe on)."""

    def __init__(self, answer):
        self.answer = answer

    def protected(self, _ip_str):
        """Return the canned answer for any address."""
        return self.answer


class FakeCompleted:
    """The fields of subprocess.CompletedProcess the responder reads."""

    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeSubprocess:
    """Stand-in for the subprocess module, recording each command."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, cmd, **_kwargs):
        """Record the command and return the canned result."""
        self.calls.append(cmd)
        return self.result


class ResponderFixture(unittest.TestCase):
    """A responder state whose journal, kv file, and sids.conf live in a
    temporary directory, with a recording block action."""

    def setUp(self):
        self.tmp = ngtest.temp_dir(self)
        self.journal_path = os.path.join(self.tmp, "blocks.json")
        self.sids_path = os.path.join(self.tmp, "sids.conf")
        self.boot_path = os.path.join(self.tmp, "boot_id")
        self.set_boot(BOOT_ID)
        ngtest.patch_attrs(self, responder,
                           RESP_KV=os.path.join(self.tmp, "responder.kv"),
                           BOOT_ID_PATH=self.boot_path)
        self.blocks = []

    def set_boot(self, value):
        """Point the fixture's boot-id file at one boot; a later value
        stands in for the host having rebooted."""
        with open(self.boot_path, "w") as f:
            f.write(value + "\n")

    def write_journal(self, records, boot=BOOT_ID):
        """Write a journal file as the responder persists it, or without
        the reserved metadata record when boot is None (a journal from
        before boot-id recording)."""
        data = dict(records)
        if boot is not None:
            data[responder.JOURNAL_META_KEY] = {"boot_id": boot}
        with open(self.journal_path, "w") as f:
            json.dump(data, f)

    def record_block(self, src, ttl):
        """Recording stand-in for the nodeguard-block wrapper."""
        self.blocks.append((src, ttl))
        return 0, ""

    def state(self, sids=(), allow=False, **over):
        """Build an event state; allow is the stub allow answer."""
        with open(self.sids_path, "w") as f:
            f.write("\n".join(sids) + "\n")
        conf = {"ENFORCE": "no",
                "EVE": os.path.join(self.tmp, "eve.json"),
                "JOURNAL": self.journal_path,
                "SIDS": self.sids_path,
                "TTL": str(TTL_BASE),
                "TTL_MAX": str(TTL_MAX),
                "RATE_MIN": "30",
                "RATE_HOUR": "500",
                "HOME_NETS": [ipaddress.ip_network(HOME_NET)]}
        conf.update(over)
        st = responder.make_state(conf, self.record_block)
        st.allow = FakeAllow(allow)
        return st

    def feed(self, st, line, now=None):
        """Run one line through handle_event and return what it logged."""
        with ngtest.captured_log() as log:
            responder.handle_event(line, st, now or time.time())
        return log.getvalue()

    def saved_records(self):
        """The persisted journal without the reserved metadata record,
        which is what the daemon treats as records."""
        with open(self.journal_path) as f:
            return {ip: rec for ip, rec in json.load(f).items()
                    if ip != responder.JOURNAL_META_KEY}

    def saved_meta(self):
        """The persisted reserved metadata record, or None."""
        with open(self.journal_path) as f:
            return json.load(f).get(responder.JOURNAL_META_KEY)

    def seed_journal(self, st, src=ATTACKER, **fields):
        """Put one record in the live journal and return it."""
        record = {"count": 0, "shadow_hits": 0, "blocked_until": 0,
                  "first_seen": time.time(), "last_seen": time.time()}
        record.update(fields)
        st.journal.data[src] = record
        return record


class GateTest(ResponderFixture):
    """One test per gate, in the order the module documents them."""

    def test_gate_1_non_alert_event_is_ignored(self):
        out = self.feed(self.state(), alert(event_type="flow"))
        self.assertEqual(out, "")
        self.assertEqual(self.blocks, [])
        self.assertEqual(self.saved_records(), {})

    def test_gate_2_low_severity_without_opt_in_is_dropped(self):
        st = self.state()
        out = self.feed(st, alert(alert={"signature_id": 2000,
                                         "severity": 3, "signature": "s"}))
        self.assertEqual(out, "")
        self.assertEqual(self.blocks, [])

    def test_gate_2_opt_in_sid_promotes_a_low_severity_alert(self):
        st = self.state(sids=["block 2000"], ENFORCE="yes")
        out = self.feed(st, alert(alert={"signature_id": 2000,
                                         "severity": 3, "signature": "s"}))
        self.assertIn("BLOCKED:", out)
        self.assertEqual(self.blocks, [(ATTACKER, TTL_BASE)])

    def test_gate_3_ignored_sid_short_circuits(self):
        st = self.state(sids=[f"ignore {SID}"], ENFORCE="yes")
        out = self.feed(st, alert())
        self.assertEqual(out, "")
        self.assertEqual(self.blocks, [])

    def test_gate_4_non_tcp_without_udp_ok_is_not_eligible(self):
        out = self.feed(self.state(), alert(proto="UDP"))
        self.assertIn("WOULD BLOCK (udp, not eligible)", out)
        self.assertEqual(self.blocks, [])

    def test_gate_4_udp_ok_sid_is_eligible(self):
        st = self.state(sids=[f"udp-ok {SID}"], ENFORCE="yes")
        out = self.feed(st, alert(proto="UDP"))
        self.assertIn("BLOCKED:", out)

    def test_gate_4_tcp_without_bidirectional_evidence_is_refused(self):
        st = self.state(ENFORCE="yes")
        out = self.feed(st, alert(flow={"pkts_toclient": 0,
                                        "pkts_toserver": 9}))
        self.assertIn("no bidirectional flow evidence", out)
        self.assertEqual(self.blocks, [])
        out = self.feed(st, alert(flow={"pkts_toclient": 5,
                                        "pkts_toserver": 1}))
        self.assertIn("no bidirectional flow evidence", out)
        self.assertEqual(self.blocks, [])

    def test_gate_5_outbound_destination_is_skipped(self):
        st = self.state(ENFORCE="yes")
        out = self.feed(st, alert(dest_ip="198.51.100.4"))
        self.assertEqual(out, "")
        self.assertEqual(self.blocks, [])

    def test_gate_5_non_global_source_is_skipped(self):
        st = self.state(ENFORCE="yes")
        out = self.feed(st, alert(src_ip="10.1.2.3"))
        self.assertEqual(out, "")
        self.assertEqual(self.blocks, [])

    def test_gate_5_unparsable_address_counts_as_malformed(self):
        st = self.state(ENFORCE="yes")
        self.feed(st, alert(src_ip="not-an-ip"))
        self.assertEqual(st.malformed, 1)
        self.assertEqual(self.blocks, [])

    def test_gate_6_protected_source_is_skipped(self):
        st = self.state(allow=True, ENFORCE="yes")
        out = self.feed(st, alert())
        self.assertIn("skip (allowlisted/protected)", out)
        self.assertEqual(self.blocks, [])

    def test_gate_6_undeterminable_allowlist_fails_toward_not_blocking(self):
        st = self.state(allow=None, ENFORCE="yes")
        out = self.feed(st, alert())
        self.assertIn("skip (allowlist undeterminable", out)
        self.assertEqual(self.blocks, [])

    def test_gate_7_minute_cap_suppresses_new_blocks(self):
        # Finding S6: a capped source with no journal record gets none,
        # because creating one is the inflation the storm buys for free.
        # The suppression itself is exercised in test_responder_journal.
        st = self.state(ENFORCE="yes", RATE_MIN="1")
        self.feed(st, alert())
        out = self.feed(st, alert(src_ip=ATTACKER_2))
        self.assertIn("RATE CAP hit", out)
        self.assertEqual(self.blocks, [(ATTACKER, TTL_BASE)])
        self.assertNotIn(ATTACKER_2, st.journal.data)
        self.assertEqual(st.capped_suppressed, 1)

    def test_gate_7_hourly_distinct_cap_suppresses_new_blocks(self):
        st = self.state(ENFORCE="yes", RATE_HOUR="1")
        self.feed(st, alert())
        out = self.feed(st, alert(src_ip=ATTACKER_2))
        self.assertIn("RATE CAP hit", out)
        self.assertEqual(len(self.blocks), 1)

    def test_all_gates_passed_blocks_in_enforce_mode(self):
        st = self.state(ENFORCE="yes")
        out = self.feed(st, alert())
        self.assertIn("BLOCKED:", out)
        self.assertEqual(self.blocks, [(ATTACKER, TTL_BASE)])
        self.assertEqual(st.journal.data[ATTACKER]["count"], 1)
        self.assertEqual(st.sec["resp_blocks_issued"], 1)

    def test_all_gates_passed_logs_would_block_in_dry_run(self):
        st = self.state()
        out = self.feed(st, alert())
        self.assertIn("WOULD BLOCK:", out)
        self.assertEqual(self.blocks, [])
        record = st.journal.data[ATTACKER]
        self.assertEqual(record["shadow_hits"], 1)
        self.assertEqual(record["count"], 0)
        self.assertGreater(record["blocked_until"], time.time())
        self.assertEqual(st.sec["resp_dryrun_would_block"], 1)

    def test_block_failure_is_logged_and_not_journaled(self):
        st = self.state(ENFORCE="yes")
        st.block_fn = lambda _src, _ttl: (1, "map not pinned")
        out = self.feed(st, alert())
        self.assertIn("block FAILED (map not pinned)", out)
        self.assertEqual(st.journal.data.get(ATTACKER, {}).get("count", 0), 0)

    def test_window_suppression_records_a_sighting(self):
        # Same-boot suppression, which finding S3's boot scoping keeps: the
        # kernel entry genuinely covers this source. The across-a-reboot
        # half is JournalBootTest.
        st = self.state(ENFORCE="yes")
        self.seed_journal(st, count=1, blocked_until=time.time() + 600)
        out = self.feed(st, alert())
        self.assertEqual(out, "")
        self.assertEqual(self.blocks, [])
        self.assertEqual(st.journal.data[ATTACKER]["shadow_hits"], 1)
        self.assertEqual(st.journal.data[ATTACKER]["count"], 1)


class EscalationTest(ResponderFixture):
    """TTL escalation counts completed block windows, not alert lines."""

    def test_ttl_doubles_per_completed_offense(self):
        for count, expected in ((0, 3600), (1, 7200), (2, 14400),
                                (3, 28800)):
            with self.subTest(count=count):
                self.blocks = []
                st = self.state(ENFORCE="yes")
                self.seed_journal(st, count=count)
                self.feed(st, alert())
                self.assertEqual(self.blocks, [(ATTACKER, expected)])

    def test_ttl_clamps_at_ttl_max(self):
        st = self.state(ENFORCE="yes")
        self.seed_journal(st, count=20)
        self.feed(st, alert())
        self.assertEqual(self.blocks, [(ATTACKER, TTL_MAX)])

    def test_real_block_raises_count_and_dry_run_raises_shadow_hits(self):
        st = self.state(ENFORCE="yes")
        self.feed(st, alert())
        self.assertEqual(st.journal.data[ATTACKER]["count"], 1)
        self.assertEqual(st.journal.data[ATTACKER]["shadow_hits"], 0)

        # A second source, because the first is now inside its window.
        shadow = self.state()
        self.feed(shadow, alert(src_ip=ATTACKER_2))
        self.assertEqual(shadow.journal.data[ATTACKER_2]["count"], 0)
        self.assertEqual(shadow.journal.data[ATTACKER_2]["shadow_hits"], 1)

    def test_rate_caps_account_identically_in_both_modes(self):
        # The caps themselves are mode-independent, and so is finding
        # S6's record suppression: neither mode journals a previously
        # unseen source while the cap is engaged.
        for enforce in ("yes", "no"):
            with self.subTest(enforce=enforce):
                self.blocks = []
                # Each mode gets its own journal; a window left by the
                # other mode would suppress the first event.
                st = self.state(
                    ENFORCE=enforce, RATE_MIN="1",
                    JOURNAL=os.path.join(self.tmp, f"blocks-{enforce}.json"))
                self.feed(st, alert())
                out = self.feed(st, alert(src_ip=ATTACKER_2))
                word = "RATE CAP" if enforce == "yes" else "WOULD RATE-CAP"
                self.assertIn(f"{word} hit", out)
                self.assertNotIn(ATTACKER_2, st.journal.data)
                self.assertEqual(st.capped_suppressed, 1)
                self.assertEqual(len(st.minute), 1)

    def test_capped_episode_collapses_repeated_logging(self):
        st = self.state(ENFORCE="yes", RATE_MIN="1")
        self.feed(st, alert())
        first = self.feed(st, alert(src_ip=ATTACKER_2))
        second = self.feed(st, alert(src_ip="1.2.3.6"))
        self.assertIn("RATE CAP hit", first)
        self.assertEqual(second, "")
        self.assertTrue(st.capped_episode)


class JournalTest(ResponderFixture):
    """The journal survives damage and stays bounded."""

    def test_records_idle_past_the_horizon_are_pruned(self):
        stale = time.time() - 31 * 86400
        with open(self.journal_path, "w") as f:
            json.dump({"203.0.113.1": {"count": 1, "last_seen": stale},
                       "203.0.113.2": {"count": 1,
                                       "last_seen": time.time()}}, f)
        journal = responder.Journal(self.journal_path)
        self.assertEqual(list(journal.data), ["203.0.113.2"])
        self.assertEqual(list(self.saved_records()), ["203.0.113.2"])

    def test_corrupt_journal_is_quarantined_and_startup_continues(self):
        with open(self.journal_path, "w") as f:
            f.write("{this is not json")
        with ngtest.captured_log() as log:
            journal = responder.Journal(self.journal_path)
        self.assertEqual(journal.data, {})
        self.assertTrue(os.path.exists(self.journal_path + ".corrupt"))
        self.assertIn("journal unreadable", log.getvalue())

    def test_non_object_journal_root_is_quarantined(self):
        with open(self.journal_path, "w") as f:
            json.dump(["not", "an", "object"], f)
        with ngtest.captured_log():
            journal = responder.Journal(self.journal_path)
        self.assertEqual(journal.data, {})
        self.assertTrue(os.path.exists(self.journal_path + ".corrupt"))


class JournalBootTest(ResponderFixture):
    """Finding S3: a block window outlives the kernel entry it stands for
    when the host reboots, because bpffs maps and CLOCK_MONOTONIC do not
    survive. Windows are therefore scoped to the boot that wrote them."""

    def record(self, **fields):
        """One journaled offender with a window still an hour out."""
        rec = {"count": 3, "shadow_hits": 2, "blocked_until": time.time() + 3600,
               "first_seen": 1.0, "last_seen": time.time(), "sid": SID}
        rec.update(fields)
        return {ATTACKER: rec}

    def test_prior_boot_windows_expire_and_counts_survive(self):
        self.write_journal(self.record(), boot=OTHER_BOOT_ID)
        with ngtest.captured_log() as log:
            journal = responder.Journal(self.journal_path)
        rec = journal.data[ATTACKER]
        self.assertEqual(rec["blocked_until"], 0)
        self.assertEqual(rec["count"], 3)
        self.assertEqual(rec["shadow_hits"], 2)
        self.assertEqual(rec["first_seen"], 1.0)
        self.assertEqual(rec["sid"], SID)
        self.assertIn("block windows treated as expired", log.getvalue())

    def test_same_boot_windows_load_unchanged(self):
        records = self.record()
        self.write_journal(records)
        with ngtest.captured_log() as log:
            journal = responder.Journal(self.journal_path)
        self.assertEqual(journal.data[ATTACKER]["blocked_until"],
                         records[ATTACKER]["blocked_until"])
        self.assertEqual(log.getvalue(), "")

    def test_legacy_journal_without_meta_loads_and_expires(self):
        self.write_journal(self.record(), boot=None)
        with ngtest.captured_log():
            journal = responder.Journal(self.journal_path)
        self.assertEqual(journal.data[ATTACKER]["blocked_until"], 0)
        self.assertEqual(journal.data[ATTACKER]["count"], 3)

    def test_meta_is_never_a_record_and_is_written_back(self):
        self.write_journal(self.record())
        with ngtest.captured_log():
            journal = responder.Journal(self.journal_path)
        self.assertNotIn(responder.JOURNAL_META_KEY, journal.data)
        self.assertEqual(list(self.saved_records()), [ATTACKER])
        self.assertEqual(self.saved_meta(), {"boot_id": BOOT_ID})

    def test_repeat_offender_is_reblocked_after_a_reboot(self):
        # The end-to-end shape of the finding: the same alert that was a
        # silent sighting before the reboot must issue a block after it,
        # and at the escalated TTL the retained count earns.
        self.write_journal(self.record(count=1))
        with ngtest.captured_log():
            warm = self.state(ENFORCE="yes")
        self.assertEqual(self.feed(warm, alert()), "")
        self.assertEqual(self.blocks, [])

        self.set_boot(OTHER_BOOT_ID)
        with ngtest.captured_log():
            rebooted = self.state(ENFORCE="yes")
        out = self.feed(rebooted, alert())
        self.assertIn("BLOCKED:", out)
        self.assertEqual(self.blocks, [(ATTACKER, TTL_BASE * 2)])
        self.assertEqual(rebooted.journal.data[ATTACKER]["count"], 2)

    def test_unreadable_boot_id_expires_windows(self):
        # Failing toward one redundant block, never toward suppression.
        self.write_journal(self.record())
        ngtest.patch_attrs(self, responder,
                           BOOT_ID_PATH=os.path.join(self.tmp, "absent"))
        with ngtest.captured_log():
            journal = responder.Journal(self.journal_path)
        self.assertEqual(journal.data[ATTACKER]["blocked_until"], 0)

    def test_unreadable_boot_id_at_both_ends_still_expires_windows(self):
        # The case an empty stamp would break: unreadable when the journal
        # was written AND when it is read back. An empty id must not
        # compare equal to itself across the reboot, so save() writes no
        # stamp at all and the reload sees a prior-boot journal.
        ngtest.patch_attrs(self, responder,
                           BOOT_ID_PATH=os.path.join(self.tmp, "absent"))
        with ngtest.captured_log():
            journal = responder.Journal(self.journal_path)
        journal.data.update(self.record())
        journal.save()
        self.assertIsNone(self.saved_meta())
        with ngtest.captured_log() as log:
            reloaded = responder.Journal(self.journal_path)
        self.assertEqual(reloaded.data[ATTACKER]["blocked_until"], 0)
        self.assertEqual(reloaded.data[ATTACKER]["count"], 3)
        self.assertIn("block windows treated as expired", log.getvalue())


class AllowCacheTest(ResponderFixture):
    """The allow cache's documented None contract."""

    def test_failed_allow_dump_returns_none_and_handle_event_skips(self):
        fake = FakeSubprocess(FakeCompleted(1, stderr="maps not pinned"))
        ngtest.patch_attrs(self, responder, subprocess=fake)
        st = self.state(ENFORCE="yes")
        st.allow = responder.AllowCache()
        with ngtest.captured_log():
            self.assertIsNone(st.allow.protected(ATTACKER))
        out = self.feed(st, alert())
        self.assertIn("skip (allowlist undeterminable", out)
        self.assertEqual(self.blocks, [])

    def test_successful_allow_dump_answers_from_the_snapshot(self):
        fake = FakeSubprocess(FakeCompleted(0, stdout='["198.51.100.0/24"]'))
        ngtest.patch_attrs(self, responder, subprocess=fake)
        cache = responder.AllowCache()
        self.assertTrue(cache.protected("198.51.100.9"))
        self.assertFalse(cache.protected(ATTACKER))
        self.assertEqual(len(fake.calls), 1)  # one dump per TTL window


class SleepBudgetExceeded(AssertionError):
    """A faked wait loop slept past its budget without yielding. An
    AssertionError so unittest reports a failure: a wait loop that stops
    yielding would otherwise spin inside next() and hang the whole run."""


class FakeClock:
    """Stand-in for the time module inside follow(): a sleep is recorded
    rather than taken, so the wait branches run at test speed. The
    recorded sleeps are budgeted, because a generator that sleeps without
    yielding never returns to the test and a hang carries no diagnostic."""

    MAX_SLEEPS = 8

    def __init__(self):
        self.sleeps = []

    def sleep(self, seconds):
        """Record the requested sleep and return immediately, until the
        budget is spent; past that the wait loop is not yielding and the
        test has to fail rather than block."""
        self.sleeps.append(seconds)
        if len(self.sleeps) > self.MAX_SLEEPS:
            raise SleepBudgetExceeded(
                "the wait loop slept %d times without yielding"
                % len(self.sleeps))

    def time(self):
        """Wall clock, unchanged; only sleeping is faked."""
        return time.time()

    def monotonic(self):
        """Monotonic clock, unchanged; only sleeping is faked."""
        return time.monotonic()


class KvHeartbeatTest(ResponderFixture):
    """Finding O1: a wedged responder served its last kv values forever.
    The flush is still debounced, but a live event loop now rewrites the
    file at least once per heartbeat interval and stamps every write."""

    def kv_fields(self):
        """The published kv file as {key: value}."""
        with open(responder.RESP_KV) as f:
            return dict(line.strip().split("=", 1) for line in f if line.strip())

    def kv_inode(self):
        """The published file's inode. Every flush publishes through a
        fresh temp file and a rename, so a changed inode is proof the
        file was rewritten and an unchanged one proof it was not."""
        return os.stat(responder.RESP_KV).st_ino

    def flushed_state(self):
        """A state whose first flush has already published a kv file."""
        st = self.state()
        st.flush_sec()
        return st

    def age_flush(self, st, seconds):
        """Backdate the last flush by seconds, standing in for the
        passage of time without sleeping through it."""
        st.sec_last_flush = time.time() - seconds

    def test_every_flush_stamps_the_kv_timestamp(self):
        st = self.flushed_state()
        fields = self.kv_fields()
        self.assertIn("ng.resp_kv_ts", fields)
        self.assertLessEqual(abs(int(fields["ng.resp_kv_ts"]) - time.time()), 5)
        self.assertIn("ng.resp_lag_s", fields)

    def test_a_dirty_change_inside_the_debounce_is_not_written(self):
        st = self.flushed_state()
        inode = self.kv_inode()
        st.sec["resp_alerts_seen"] = 7
        st.sec_dirty = True

        st.flush_sec()

        self.assertEqual(self.kv_inode(), inode)
        self.assertEqual(self.kv_fields()["ng.resp_alerts_seen"], "0")

    def test_a_dirty_change_after_the_debounce_is_written(self):
        st = self.flushed_state()
        st.sec["resp_alerts_seen"] = 7
        st.sec_dirty = True
        self.age_flush(st, responder.KV_FLUSH_S)

        st.flush_sec()

        self.assertEqual(self.kv_fields()["ng.resp_alerts_seen"], "7")
        self.assertFalse(st.sec_dirty)

    def test_an_idle_responder_is_not_rewritten_before_the_heartbeat(self):
        st = self.flushed_state()
        inode = self.kv_inode()
        self.age_flush(st, responder.KV_HEARTBEAT_S - 1)

        st.flush_sec()

        self.assertEqual(self.kv_inode(), inode)

    def test_an_idle_responder_is_rewritten_at_the_heartbeat(self):
        # Quiet and dead have to be distinguishable: with nothing dirty
        # and no new alert, the file is still republished with a fresh
        # stamp.
        st = self.flushed_state()
        inode = self.kv_inode()
        stamped = int(self.kv_fields()["ng.resp_kv_ts"])
        self.age_flush(st, responder.KV_HEARTBEAT_S)

        st.flush_sec()

        self.assertNotEqual(self.kv_inode(), inode)
        self.assertGreaterEqual(int(self.kv_fields()["ng.resp_kv_ts"]),
                                stamped)

    def test_a_missing_eve_json_still_yields_the_idle_sentinel(self):
        # The one live-loop state that used to sleep and continue without
        # yielding: while eve.json is absent the responder is alive, so
        # the heartbeat must keep advancing.
        clock = FakeClock()
        ngtest.patch_attrs(self, responder, time=clock)
        stream = responder.follow(os.path.join(self.tmp, "absent.json"))
        self.addCleanup(stream.close)

        self.assertIsNone(next(stream))
        self.assertIsNone(next(stream))

        self.assertEqual(clock.sleeps[:2], [2, 2])


class AlertLagTest(ResponderFixture):
    """Finding O1: the alert-to-decision lag is measured against the EVE
    record's own timestamp, and a hostile one never fabricates a value."""

    def stamp(self, offset_s, now=NOW):
        """An EVE timestamp offset_s seconds before now, in the ISO 8601
        form with an offset that Suricata writes."""
        moment = datetime.datetime.fromtimestamp(now - offset_s,
                                                 datetime.timezone.utc)
        return moment.isoformat()

    def test_a_lag_is_measured_from_the_record_timestamp(self):
        self.assertEqual(responder.eve_lag(self.stamp(12), NOW), 12)

    def test_suricatas_compact_offset_form_parses(self):
        # Suricata writes "+0000", not "+00:00"; a parser that rejected it
        # would silently never update the lag.
        self.assertEqual(
            responder.eve_lag("2026-09-06T12:00:00.000000+0000",
                              datetime.datetime(
                                  2026, 9, 6, 12, 0, 30,
                                  tzinfo=datetime.timezone.utc).timestamp()),
            30)

    def test_a_future_dated_record_clamps_to_zero(self):
        self.assertEqual(responder.eve_lag(self.stamp(-3600), NOW), 0)

    def test_hostile_timestamps_are_unusable_rather_than_wrong(self):
        for stamp in (None, int(NOW), "", "not-a-timestamp",
                      "2026-09-06T12:00:00.000000"):
            with self.subTest(stamp=stamp):
                self.assertIsNone(responder.eve_lag(stamp, NOW))

    def test_a_consumed_alert_exports_its_lag(self):
        st = self.state()

        self.feed(st, alert(timestamp=self.stamp(9)), now=NOW)

        self.assertEqual(st.sec["resp_lag_s"], 9)

    def test_an_unusable_timestamp_leaves_the_previous_lag_in_place(self):
        st = self.state()
        st.sec["resp_lag_s"] = 7

        for line in (alert(timestamp="not-a-timestamp"), alert()):
            self.feed(st, line)

        self.assertEqual(st.sec["resp_lag_s"], 7)
        self.assertEqual(st.malformed, 0)


if __name__ == "__main__":
    unittest.main()
