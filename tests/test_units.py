#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Conformance tests for units/*.service: the systemd confinement of
evaluation finding S2.

The common hardening block is asserted against EVERY shipped unit rather
than a frozen list, so a unit added by another change cannot ship
unconfined; the per-unit writable paths, capability sets, and syscall
allowances are asserted against the tables in the change's design.md, so
the documented confinement and the shipped confinement cannot drift.
"""

import glob
import os
import unittest

import ngtest

UNITS_DIR = os.path.join(ngtest.REPO_ROOT, "units")

# The block every service unit carries, whatever it does.
COMMON = {
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
}

# design.md section 2, per-unit ReadWritePaths, entries exactly as the
# units declare them. A unit absent from this table declares no writable
# path at all.
# INVARIANT: the bpffs pin directory is spelled with systemd's "-"
# prefix. It is created at runtime and does not survive a reboot, so an
# unprefixed entry would fail the unit at namespace setup; the prefix is
# part of the declaration this table pins, not formatting.
PIN_DIR = "-/sys/fs/bpf/nodeguard"
READ_WRITE_PATHS = {
    "nodeguard-maps": {"/run/nodeguard", "/var/lib/nodeguard", PIN_DIR},
    "nodeguard-xdp": {"/run/nodeguard", PIN_DIR},
    "nodeguard-responder": {"/run/nodeguard", "/var/lib/nodeguard", PIN_DIR},
    "nodeguard-feeds": {"/run/nodeguard", "/var/lib/nodeguard", PIN_DIR},
    "nodeguard-sweep": {"/run/nodeguard", "/var/lib/nodeguard", PIN_DIR},
    "nodeguard-geo": {"/run/nodeguard", "/var/lib/nodeguard", PIN_DIR},
    "nodeguard-watchdog": {"/run/nodeguard", "/var/lib/nodeguard", PIN_DIR},
    "suricata-update": {"/var/lib/suricata", "/var/lib/nodeguard"},
    "nodeguard-allow-refresh": set(),
}

# fix-nodeguard-deploy-reliability design.md section 1, per-unit
# TimeoutStartSec. systemd defaults a Type=oneshot start timeout to
# infinity, so an unbounded unit does not fail when it hangs: it stays
# activating and its timer stops firing. The values are sized below each
# unit's own timer period (boot-path units carry a bounded value instead).
TIMEOUT_START_SEC = {
    "nodeguard-watchdog": "55s",
    "nodeguard-sweep": "8min",
    "nodeguard-geo": "4min",
    "nodeguard-feeds": "30min",
    "suricata-update": "30min",
    "nodeguard-maps": "2min",
    "nodeguard-xdp": "2min",
    "nodeguard-allow-refresh": "180",
}

# design.md section 2, per-unit CapabilityBoundingSet.
CAPABILITIES = {
    "nodeguard-maps": {"CAP_SYS_ADMIN", "CAP_BPF", "CAP_NET_ADMIN"},
    "nodeguard-xdp": {"CAP_SYS_ADMIN", "CAP_BPF", "CAP_NET_ADMIN",
                      "CAP_PERFMON"},
    "nodeguard-responder": {"CAP_SYS_ADMIN", "CAP_BPF",
                            "CAP_DAC_READ_SEARCH"},
    "nodeguard-feeds": {"CAP_SYS_ADMIN", "CAP_BPF"},
    "nodeguard-sweep": {"CAP_SYS_ADMIN", "CAP_BPF"},
    "nodeguard-geo": {"CAP_SYS_ADMIN", "CAP_BPF"},
    "nodeguard-watchdog": {"CAP_SYS_ADMIN", "CAP_BPF", "CAP_NET_ADMIN",
                           "CAP_NET_RAW", "CAP_DAC_OVERRIDE"},
    "suricata-update": {"CAP_DAC_OVERRIDE"},
    "nodeguard-allow-refresh": set(),
}

# design.md section 2: @system-service everywhere, plus the syscalls
# systemd puts in @privileged that a unit's own commands need.
BASE_SYSCALL_SET = "@system-service"
EXTRA_SYSCALLS = {
    "nodeguard-maps": {"bpf"},
    "nodeguard-xdp": {"bpf", "perf_event_open"},
    "nodeguard-responder": {"bpf"},
    "nodeguard-feeds": {"bpf"},
    "nodeguard-sweep": {"bpf"},
    "nodeguard-geo": {"bpf"},
    "nodeguard-watchdog": {"bpf"},
    "suricata-update": set(),
    "nodeguard-allow-refresh": set(),
}


def unit_files():
    """Every shipped service unit, as (name without suffix, path)."""
    found = [(os.path.basename(p)[:-len(".service")], p)
             for p in sorted(glob.glob(os.path.join(UNITS_DIR, "*.service")))]
    if not found:
        raise AssertionError(f"{UNITS_DIR}: no service units found")
    return found


def service_directives(path):
    """Return the unit's [Service] section as {key: [values]}.

    Fails loudly on a line continuation rather than mis-parsing one: the
    shipped units use none, and a silently truncated directive would let
    this whole module assert nothing.
    """
    section = None
    directives = {}
    with open(path) as f:
        for number, raw in enumerate(f, start=1):
            line = raw.strip()
            if line.endswith("\\"):
                raise AssertionError(
                    f"{path}:{number}: line continuation, which this "
                    "parser does not implement")
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if section != "Service" or "=" not in line:
                continue
            key, value = line.split("=", 1)
            directives.setdefault(key.strip(), []).append(value.strip())
    return directives


class CommonHardeningTest(unittest.TestCase):
    """Every unit present, not a frozen list of the ones S2 enumerated."""

    def test_every_service_unit_carries_the_common_block(self):
        for name, path in unit_files():
            directives = service_directives(path)
            for key, expected in COMMON.items():
                with self.subTest(unit=name, directive=key):
                    self.assertEqual(directives.get(key), [expected])

    def test_every_service_unit_filters_syscalls(self):
        for name, path in unit_files():
            with self.subTest(unit=name):
                values = service_directives(path).get("SystemCallFilter")
                self.assertIsNotNone(values)
                self.assertEqual(len(values), 1)
                self.assertIn(BASE_SYSCALL_SET, values[0].split())

    def test_every_oneshot_unit_bounds_its_start(self):
        for name, path in unit_files():
            directives = service_directives(path)
            if directives.get("Type") != ["oneshot"]:
                continue
            with self.subTest(unit=name):
                self.assertEqual(directives.get("TimeoutStartSec"),
                                 [TIMEOUT_START_SEC.get(name)])

    def test_every_service_unit_bounds_its_capabilities(self):
        for name, path in unit_files():
            with self.subTest(unit=name):
                values = service_directives(path).get("CapabilityBoundingSet")
                self.assertIsNotNone(values)
                self.assertEqual(len(values), 1)


class PerUnitDirectiveTest(unittest.TestCase):
    """The design's per-unit tables, unit by unit."""

    def directives(self, name):
        """The [Service] directives of one named unit, failing when the
        unit the table names is not shipped at all."""
        path = os.path.join(UNITS_DIR, f"{name}.service")
        self.assertTrue(os.path.exists(path), f"{path} is missing")
        return service_directives(path)

    def test_read_write_paths_match_the_design_table(self):
        for name, expected in READ_WRITE_PATHS.items():
            with self.subTest(unit=name):
                values = self.directives(name).get("ReadWritePaths", [])
                declared = set()
                for value in values:
                    declared.update(value.split())
                self.assertEqual(declared, expected)

    def test_capability_bounding_sets_match_the_design_table(self):
        for name, expected in CAPABILITIES.items():
            with self.subTest(unit=name):
                values = self.directives(name)["CapabilityBoundingSet"]
                self.assertEqual(set(values[0].split()), expected)

    def test_bpf_units_allow_bpf_and_the_others_do_not(self):
        for name, extra in EXTRA_SYSCALLS.items():
            with self.subTest(unit=name):
                allowed = set(
                    self.directives(name)["SystemCallFilter"][0].split())
                self.assertEqual(allowed, {BASE_SYSCALL_SET} | extra)

    def test_declared_writable_paths_are_absolute(self):
        # systemd resolves a ReadWritePaths entry relative to RootDirectory
        # and these units set none, so a relative entry would leave the
        # unit read-only exactly where it has to write. The optional "-"
        # prefix (ignore a missing path) is stripped first; what has to be
        # absolute is the path behind it.
        for name, _expected in READ_WRITE_PATHS.items():
            for value in self.directives(name).get("ReadWritePaths", []):
                for entry in value.split():
                    with self.subTest(unit=name, path=entry):
                        self.assertTrue(entry.lstrip("-").startswith("/"))


if __name__ == "__main__":
    unittest.main()
