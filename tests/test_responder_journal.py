#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for the responder's journal persistence under an alert
storm (evaluation finding S6): sightings are debounced, enforced offenses
are not, a capped storm creates no new records, and a stop still drains
what is pending.

The fixture is test_responder's, so the conf, journal path, and block
recorder have one definition for the whole responder suite.
"""

import json
import signal
import time
import unittest

import ngtest
from test_responder import ATTACKER, ATTACKER_2, ResponderFixture, alert

responder = ngtest.load_bin("nodeguard_responder", "nodeguard-responder")

BURST = 50
WINDOW_S = 600
# How far inside the flush interval the not-yet-due assertion probes. A
# full second, because a zero-margin boundary would turn on wall-clock
# drift rather than on the interval the test is about.
INSIDE_INTERVAL_S = 1


class SaveCountingFixture(ResponderFixture):
    """A responder state whose journal counts its own serializations."""

    def counted(self, st):
        """Wrap the journal's save so the test can see how often the
        whole file was rewritten, and return the counter list."""
        saves = []
        original = st.journal.save

        def counting_save():
            saves.append(time.time())
            original()

        st.journal.save = counting_save
        return saves


class DebounceTest(SaveCountingFixture):
    """Sightings accumulate in memory; the flush writes them."""

    def test_a_burst_of_sightings_serializes_at_most_once_per_interval(self):
        st = self.state()
        now = time.time()
        self.seed_journal(st, blocked_until=now + WINDOW_S)
        saves = self.counted(st)

        for _ in range(BURST):
            self.feed(st, alert(), now)

        # handle_event never serializes a sighting; it marks the journal
        # dirty and the loop's flush decides when the file is written.
        self.assertEqual(saves, [])
        self.assertTrue(st.journal.dirty)

        st.journal.flush(now)
        self.assertEqual(saves, [], "flushed inside the debounce interval")

        st.journal.flush(now + responder.JOURNAL_FLUSH_S)
        self.assertEqual(len(saves), 1)
        self.assertEqual(
            self.saved_records()[ATTACKER]["shadow_hits"], BURST)

        # save() stamps last_flush from its own clock, not from the now
        # it was flushed at, so the next interval runs from the write that
        # actually happened; measuring it from the now captured above
        # lands microseconds short of due and would pass for the wrong
        # reason.
        due = st.journal.last_flush + responder.JOURNAL_FLUSH_S
        for _ in range(BURST):
            self.feed(st, alert(), now)

        st.journal.flush(due - INSIDE_INTERVAL_S)
        self.assertEqual(len(saves), 1, "second interval not yet due")

        st.journal.flush(due)
        self.assertEqual(len(saves), 2, "second interval due")

    def test_a_clean_journal_is_not_rewritten(self):
        st = self.state()
        saves = self.counted(st)

        st.journal.flush(time.time() + responder.JOURNAL_FLUSH_S)

        self.assertEqual(saves, [])

    def test_an_enforced_offense_is_persisted_immediately(self):
        st = self.state(ENFORCE="yes")
        saves = self.counted(st)

        out = self.feed(st, alert())

        self.assertIn("BLOCKED:", out)
        self.assertEqual(len(saves), 1)
        self.assertEqual(self.saved_records()[ATTACKER]["count"], 1)
        self.assertFalse(st.journal.dirty)

    def test_a_shadow_offense_is_debounced(self):
        st = self.state()
        saves = self.counted(st)

        out = self.feed(st, alert())

        self.assertIn("WOULD BLOCK:", out)
        self.assertEqual(saves, [])
        self.assertTrue(st.journal.dirty)


class CappedRecordTest(ResponderFixture):
    """While the rate cap is engaged the journal cannot be inflated."""

    def capped(self, now):
        """A state whose one-per-minute cap is already spent on
        ATTACKER, so every further new source is capped."""
        st = self.state(ENFORCE="yes", RATE_MIN="1")
        self.feed(st, alert(), now)
        return st

    def test_an_unseen_capped_source_gets_no_record(self):
        now = time.time()
        st = self.capped(now)

        out = self.feed(st, alert(src_ip=ATTACKER_2), now)

        self.assertIn("RATE CAP hit", out)
        self.assertIn("1 unseen source(s) not journaled", out)
        self.assertNotIn(ATTACKER_2, st.journal.data)
        self.assertEqual(st.capped_suppressed, 1)

    def test_suppressed_creations_accumulate_across_the_episode(self):
        now = time.time()
        st = self.capped(now)

        self.feed(st, alert(src_ip=ATTACKER_2), now)
        self.feed(st, alert(src_ip="1.2.3.6"), now)
        self.feed(st, alert(src_ip="1.2.3.7"), now)

        self.assertEqual(st.capped_suppressed, 3)
        self.assertEqual(set(st.journal.data), {ATTACKER})

    def test_a_known_source_still_refreshes_while_capped(self):
        now = time.time()
        st = self.capped(now)
        record = self.seed_journal(st, src=ATTACKER_2, shadow_hits=4)

        self.feed(st, alert(src_ip=ATTACKER_2), now)

        self.assertEqual(record["shadow_hits"], 5)
        self.assertEqual(st.capped_suppressed, 0)

    def test_the_episode_end_reports_what_it_suppressed(self):
        now = time.time()
        st = self.capped(now)
        self.feed(st, alert(src_ip=ATTACKER_2), now)

        # A minute later the cap's window has slid, so this source is
        # not capped: the episode ends, which is where its total becomes
        # knowable and therefore where it is reported.
        out = self.feed(st, alert(src_ip="1.2.3.6"), now + 61)

        self.assertIn("rate cap episode over; 1 unseen source(s)", out)
        self.assertFalse(st.capped_episode)
        self.assertEqual(st.capped_suppressed, 0)


class ShutdownTest(ResponderFixture):
    """A stop must not discard the sightings inside the interval."""

    def setUp(self):
        super().setUp()
        # The handler is process-wide state; put back whatever this
        # process had before the test armed its own.
        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)

    def run_daemon(self, st, ending):
        """Run the daemon's entry point over one alert line, with the
        tail replaced by a generator that ends the way ending says."""
        def fake_follow(_path):
            yield alert()
            raise ending

        ngtest.patch_attrs(self, responder,
                           load_conf=lambda: st.conf,
                           make_state=lambda _conf: st,
                           follow=fake_follow)
        with ngtest.captured_log() as log:
            with self.assertRaises(ending):
                responder.main()
        return log.getvalue()

    def persisted(self):
        """The journal as it exists on disk right now."""
        with open(self.journal_path) as f:
            return json.load(f)

    def test_sigterm_handler_is_installed_and_raises_system_exit(self):
        responder.install_sigterm_handler()

        self.assertIs(signal.getsignal(signal.SIGTERM), responder.terminate)
        with self.assertRaises(SystemExit):
            responder.terminate(signal.SIGTERM, None)

    def test_systemd_stop_flushes_pending_state(self):
        st = self.state()

        self.run_daemon(st, SystemExit)

        # The dry-run shadow offense was pending inside the debounce
        # interval; the finally around the loop is what saved it.
        self.assertEqual(
            self.persisted()[ATTACKER]["shadow_hits"], 1)
        self.assertFalse(st.journal.dirty)

    def test_keyboard_interrupt_flushes_pending_state(self):
        st = self.state()

        self.run_daemon(st, KeyboardInterrupt)

        self.assertEqual(
            self.persisted()[ATTACKER]["shadow_hits"], 1)

    def test_the_daemon_arms_the_handler_before_the_loop(self):
        st = self.state()

        self.run_daemon(st, SystemExit)

        self.assertIs(signal.getsignal(signal.SIGTERM), responder.terminate)


if __name__ == "__main__":
    unittest.main()
