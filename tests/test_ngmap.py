#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for bin/ngmap.py: the map key and value encoders, the
never-block and containment guards, the block command's refusal ladder,
and the integer-range refusals that keep an operator invocation from
ending in a packing traceback (evaluation finding K3)."""

import argparse
import ipaddress
import struct
import unittest

import ngtest

ngmap = ngtest.load_bin("ngmap", "ngmap.py")

V4_PREFIXES = (0, 8, 16, 24, 32)
V6_PREFIXES = (0, 32, 48, 64, 128)
U64_CEILING = 2 ** 64
# A fixed CLOCK_MONOTONIC reading, so an expiry in a test is exactly as
# far past or future as the test says.
NOW_NS = 1_000_000_000
TARGET = "203.0.113.7"
COVERING = "203.0.113.0/24"


def block_args(target, ttl=3600, permanent=False, i_mean_it=False):
    """Build the parsed-argument namespace cmd_block expects."""
    return argparse.Namespace(target=target, ttl=ttl, permanent=permanent,
                              i_mean_it=i_mean_it)


class EncoderTest(unittest.TestCase):
    """Key and value encoders round-trip for both address families."""

    def test_key_bytes_decode_key_round_trip_v4(self):
        for prefixlen in V4_PREFIXES:
            net = ipaddress.ip_network(f"203.0.113.0/{prefixlen}",
                                       strict=False)
            with self.subTest(net=str(net)):
                raw = ngmap.key_bytes(net)
                self.assertEqual(len(raw), 8)
                self.assertEqual(ngmap.decode_key(raw), net)

    def test_key_bytes_decode_key_round_trip_v6(self):
        for prefixlen in V6_PREFIXES:
            net = ipaddress.ip_network(f"2001:db8:1234::/{prefixlen}",
                                       strict=False)
            with self.subTest(net=str(net)):
                raw = ngmap.key_bytes(net)
                self.assertEqual(len(raw), 20)
                self.assertEqual(ngmap.decode_key(raw), net)

    def test_key_bytes_carries_the_prefix_length_first(self):
        net = ipaddress.ip_network("203.0.113.0/24")
        raw = ngmap.key_bytes(net)
        self.assertEqual(struct.unpack("<I", raw[:4])[0], 24)
        self.assertEqual(raw[4:], net.network_address.packed)

    def test_bytes_to_args_round_trip(self):
        raw = bytes(range(0, 256, 7))
        args = ngmap.bytes_to_args(raw)
        self.assertTrue(all(a.startswith("0x") for a in args))
        self.assertEqual(ngmap.args_to_bytes(args), raw)


class GuardTest(unittest.TestCase):
    """NEVER_BLOCK and containment refusals, the guards every block path
    depends on."""

    def test_every_never_block_range_is_refused_with_its_reason(self):
        for net in ngmap.NEVER_BLOCK:
            with self.subTest(net=str(net)):
                reason = ngmap.is_protected(str(net.network_address))
                self.assertIsNotNone(reason)
                self.assertIn(str(net), reason)
                self.assertIn("never-block", reason)

    def test_live_allow_entry_is_refused_with_its_reason(self):
        allow = [ipaddress.ip_network("198.51.100.0/24")]
        reason = ngmap.is_protected("198.51.100.9", allow)
        self.assertEqual(reason, "allow entry 198.51.100.0/24")

    def test_routable_address_is_not_protected(self):
        self.assertIsNone(ngmap.is_protected("203.0.113.9"))

    def test_contains_protected_refuses_a_swallowing_cidr(self):
        net = ipaddress.ip_network("192.168.0.0/15")
        found = ngmap.contains_protected(net)
        self.assertEqual(found, ipaddress.ip_network("192.168.0.0/16"))

    def test_contains_protected_refuses_a_swallowed_allow_entry(self):
        allow = [ipaddress.ip_network("198.51.100.0/24")]
        net = ipaddress.ip_network("198.51.100.0/23")
        self.assertEqual(ngmap.contains_protected(net, allow),
                         ipaddress.ip_network("198.51.100.0/24"))

    def test_contains_protected_allows_an_unrelated_cidr(self):
        self.assertIsNone(
            ngmap.contains_protected(ipaddress.ip_network("203.0.113.0/24")))


class BlockCommandTest(unittest.TestCase):
    """cmd_block's refusal ladder and its one permitted write."""

    def setUp(self):
        self.fake = ngtest.FakeMaps()
        self.fake.install(self, ngmap)

    def assert_refused(self, args, needle):
        """cmd_block must refuse the arguments with a diagnostic naming
        the reason, and write nothing."""
        with ngtest.captured_error() as err:
            with self.assertRaises(SystemExit):
                ngmap.cmd_block(args)
        self.assertIn(needle, err.getvalue())
        self.assertEqual(self.fake.updates, [])

    def test_short_prefix_without_i_mean_it_is_refused(self):
        self.assert_refused(block_args("203.0.0.0/7"), "shorter than /8")

    def test_permanent_without_i_mean_it_is_refused(self):
        self.assert_refused(block_args("203.0.113.7", permanent=True),
                            "--permanent requires --i-mean-it")

    def test_nonpositive_ttl_is_refused(self):
        self.assert_refused(block_args("203.0.113.7", ttl=0),
                            "already-expired entry")

    def test_protected_target_is_refused(self):
        self.assert_refused(block_args("10.1.2.3"),
                            "never-block range 10.0.0.0/8")

    def test_allowlisted_target_is_refused(self):
        self.fake.allow.append(ipaddress.ip_network("203.0.113.0/24"))
        self.assert_refused(block_args("203.0.113.7"),
                            "allow entry 203.0.113.0/24")

    def test_broad_target_containing_a_protected_range_is_refused(self):
        # The network address itself is blockable; only the containment
        # guard sees that the CIDR would swallow 172.16.0.0/12.
        self.assert_refused(block_args("172.0.0.0/9", i_mean_it=True),
                            "contains protected range 172.16.0.0/12")

    def test_permitted_block_writes_the_expected_key_and_value(self):
        ngtest.patch_attrs(self, ngmap, mono_ns=lambda: 1_000_000_000)
        with ngtest.captured_log():
            ngmap.cmd_block(block_args("203.0.113.7", ttl=60))
        net = ipaddress.ip_network("203.0.113.7/32")
        self.assertEqual(
            self.fake.updates,
            [(ngmap.map_path(net, "block"), ngmap.key_bytes(net),
              struct.pack("<QQ", 1_000_000_000 + 60 * 10 ** 9, 0))])


class BlockValueTest(unittest.TestCase):
    """Finding K1: cmd_block reads the existing value before writing, so a
    manual permanent entry is never demoted by automation and a live
    entry's hits survive the refresh."""

    def setUp(self):
        self.fake = ngtest.FakeMaps()
        self.fake.install(self, ngmap)
        ngtest.patch_attrs(self, ngmap, mono_ns=lambda: NOW_NS)
        self.net = ipaddress.ip_network(f"{TARGET}/32")
        self.path = ngmap.map_path(self.net, "block")

    def seed(self, expiry, hits):
        """Put one block entry in the fake map and forget the call, so a
        later assertion sees only what cmd_block wrote."""
        self.fake.update_map(self.path, ngmap.key_bytes(self.net),
                             struct.pack("<QQ", expiry, hits))
        self.fake.updates.clear()

    def written(self):
        """The (expiry, hits) cmd_block wrote for the fixture's target."""
        self.assertEqual(len(self.fake.updates), 1, self.fake.updates)
        path, key, value = self.fake.updates[0]
        self.assertEqual((path, key), (self.path, ngmap.key_bytes(self.net)))
        return struct.unpack("<QQ", value)

    def test_absent_entry_is_written_fresh(self):
        with ngtest.captured_log():
            ngmap.cmd_block(block_args(TARGET, ttl=60))
        self.assertEqual(self.written(), (NOW_NS + 60 * 10 ** 9, 0))

    def test_permanent_entry_is_not_demoted_by_automation(self):
        self.seed(expiry=0, hits=99)
        with ngtest.captured_error() as err:
            with self.assertRaises(SystemExit):
                ngmap.cmd_block(block_args(TARGET, ttl=60))
        self.assertIn("PERMANENT", err.getvalue())
        self.assertIn("--i-mean-it", err.getvalue())
        self.assertEqual(self.fake.updates, [])
        self.assertEqual(
            struct.unpack("<QQ", self.fake.lookup_value(
                self.path, ngmap.key_bytes(self.net))), (0, 99))

    def test_permanent_entry_is_overwritten_with_the_flag(self):
        self.seed(expiry=0, hits=99)
        with ngtest.captured_log():
            ngmap.cmd_block(block_args(TARGET, ttl=60, i_mean_it=True))
        self.assertEqual(self.written(), (NOW_NS + 60 * 10 ** 9, 99))

    def test_live_entry_refresh_carries_hits_forward(self):
        self.seed(expiry=NOW_NS + 10 ** 9, hits=4242)
        with ngtest.captured_log():
            ngmap.cmd_block(block_args(TARGET, ttl=60))
        self.assertEqual(self.written(), (NOW_NS + 60 * 10 ** 9, 4242))

    def test_expired_entry_is_treated_as_absent(self):
        self.seed(expiry=NOW_NS - 1, hits=4242)
        with ngtest.captured_log():
            ngmap.cmd_block(block_args(TARGET, ttl=60))
        self.assertEqual(self.written(), (NOW_NS + 60 * 10 ** 9, 0))


class ContainedExpiredTest(unittest.TestCase):
    """Finding K2: the kernel makes one LPM lookup, so an expired
    more-specific entry passes its own address inside a live broader
    block. A writer that covers the corpse deletes it."""

    def setUp(self):
        self.fake = ngtest.FakeMaps()
        self.fake.install(self, ngmap)
        ngtest.patch_attrs(self, ngmap, mono_ns=lambda: NOW_NS)
        self.covering = ipaddress.ip_network(COVERING)
        self.path = ngmap.map_path(self.covering, "block")

    def put(self, cidr, expiry, hits=0):
        """Add one block entry and return its network."""
        net = ipaddress.ip_network(cidr)
        self.fake.update_map(self.path, ngmap.key_bytes(net),
                             struct.pack("<QQ", expiry, hits))
        return net

    def present(self, net):
        """Whether the fake map still holds an entry for a network."""
        return self.fake.lookup_value(
            self.path, ngmap.key_bytes(net)) is not None

    def test_expired_strict_subnet_is_deleted(self):
        corpse = self.put(f"{TARGET}/32", NOW_NS - 1)
        purged = ngmap.purge_contained_expired(self.path, self.covering)
        self.assertEqual(purged, 1)
        self.assertFalse(self.present(corpse))

    def test_live_subnet_is_kept(self):
        live = self.put(f"{TARGET}/32", NOW_NS + 10 ** 9)
        self.assertEqual(
            ngmap.purge_contained_expired(self.path, self.covering), 0)
        self.assertTrue(self.present(live))

    def test_permanent_subnet_is_kept(self):
        permanent = self.put(f"{TARGET}/32", 0)
        self.assertEqual(
            ngmap.purge_contained_expired(self.path, self.covering), 0)
        self.assertTrue(self.present(permanent))

    def test_equal_length_key_is_untouched(self):
        same = self.put(COVERING, NOW_NS - 1)
        self.assertEqual(
            ngmap.purge_contained_expired(self.path, self.covering), 0)
        self.assertTrue(self.present(same))

    def test_entry_outside_the_covering_network_is_untouched(self):
        outside = self.put("198.51.100.7/32", NOW_NS - 1)
        self.assertEqual(
            ngmap.purge_contained_expired(self.path, self.covering), 0)
        self.assertTrue(self.present(outside))

    def test_candidate_revived_since_the_snapshot_is_kept(self):
        # The bulk path snapshots corpses once per run; the under-lock
        # re-verification is what authorizes each delete, so a key another
        # writer re-blocked in between survives.
        candidates = [self.put(f"{TARGET}/32", NOW_NS - 1)]
        revived = self.put(f"{TARGET}/32", NOW_NS + 10 ** 9)
        self.assertEqual(
            ngmap.purge_contained_expired(self.path, self.covering,
                                          candidates), 0)
        self.assertTrue(self.present(revived))

    def test_candidate_deleted_since_the_snapshot_is_tolerated(self):
        candidates = [ipaddress.ip_network(f"{TARGET}/32")]
        self.assertEqual(
            ngmap.purge_contained_expired(self.path, self.covering,
                                          candidates), 0)
        self.assertEqual(self.fake.deletes, [])

    def test_a_cidr_block_purges_its_contained_corpse(self):
        corpse = self.put(f"{TARGET}/32", NOW_NS - 1)
        with ngtest.captured_log() as out:
            ngmap.cmd_block(block_args(COVERING))
        self.assertFalse(self.present(corpse))
        self.assertIn("purged 1 contained expired entries", out.getvalue())

    def test_a_host_block_purges_nothing(self):
        corpse = self.put(f"{TARGET}/32", NOW_NS - 1)
        with ngtest.captured_log():
            ngmap.cmd_block(block_args("203.0.113.9"))
        # A host route cannot strictly contain anything, so the dump the
        # purge would need never happens.
        self.assertTrue(self.present(corpse))


class IntegerRangeTest(unittest.TestCase):
    """Finding K3: an out-of-range operator integer must reach the tool's
    one-line diagnostic path, never struct.pack. Every case runs through
    main() because that is where an operator meets the failure."""

    def setUp(self):
        self.fake = ngtest.FakeMaps()
        self.fake.install(self, ngmap)

    def assert_clean_refusal(self, argv, needle):
        """Assert the CLI refuses argv with a nonzero exit and a one-line
        diagnostic naming the offending value, and writes nothing."""
        code, out, err = ngtest.run_main(ngmap, argv)
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertTrue(err.startswith("ngmap: "), err)
        self.assertIn(needle, err)
        self.assertEqual(self.fake.updates, [])

    def test_negative_slot_is_refused(self):
        self.assert_clean_refusal(["set-config", "-1", "1"], "-1")

    def test_negative_value_is_refused(self):
        self.assert_clean_refusal(["set-config", "1", "-1"], "-1")

    def test_value_at_the_64_bit_ceiling_is_refused(self):
        self.assert_clean_refusal(["set-config", "1", str(U64_CEILING)],
                                  str(U64_CEILING))

    def test_expiry_overflowing_ttl_is_refused(self):
        self.assert_clean_refusal(
            ["block", "203.0.113.7", "--ttl", str(U64_CEILING)], "--ttl")

    def test_kill_switch_latch_still_writes(self):
        code, _out, err = ngtest.run_main(ngmap, ["set-config", "1", "1"])
        self.assertEqual(code, 0, err)
        self.assertEqual(
            self.fake.updates,
            [(f"{ngmap.PIN}/config", struct.pack("<I", 1),
              struct.pack("<Q", 1))])

    def test_maximal_in_range_value_round_trips(self):
        top = U64_CEILING - 1
        code, _out, err = ngtest.run_main(ngmap, ["set-config", "3", str(top)])
        self.assertEqual(code, 0, err)
        path, key, value = self.fake.updates[0]
        self.assertEqual(path, f"{ngmap.PIN}/config")
        self.assertEqual(struct.unpack("<I", key)[0], 3)
        self.assertEqual(struct.unpack("<Q", value)[0], top)


if __name__ == "__main__":
    unittest.main()
