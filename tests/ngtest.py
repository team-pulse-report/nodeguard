#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Shared harness for the nodeguard unit suite.

Provides the loader for the extensionless bin/ scripts, the extractor for
the watchdog's embedded anomaly detector, and the fakes that stand in for
every subprocess and transport boundary.

INVARIANT: the suite is hermetic. Stdlib only, no root, no network, no
bpftool, no bpffs, and no write outside a temporary directory the test
created. Nothing in this file performs a real map operation.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(REPO_ROOT, "bin")
BUILD_DIR = os.path.join(REPO_ROOT, "build")
WATCHDOG = os.path.join(BIN_DIR, "nodeguard-watchdog")

# Heredoc delimiter of the watchdog's embedded anomaly detector. The other
# heredocs in that script use different delimiters, so this one is unique.
ANOM_MARKER = "ANOMPY"

_MODULE_CACHE = {}


def load_bin(module_name, filename):
    """Load one bin/ script as a module and return it, cached per run.

    The programs under test mostly have no .py suffix, and
    importlib.util.spec_from_file_location picks its loader from the
    suffix, so an explicit SourceFileLoader is used instead.
    """
    if module_name in _MODULE_CACHE:
        return _MODULE_CACHE[module_name]
    if module_name != "ngmap":
        # bin/nodeguard-feeds does `import ngmap` after prepending the
        # installed library directory (absent on a dev machine). Loading
        # and registering ngmap first makes that import resolve to the
        # repo copy the tests patch, never to an installed one.
        load_bin("ngmap", "ngmap.py")
    if BIN_DIR not in sys.path:
        sys.path.insert(0, BIN_DIR)
    path = os.path.join(BIN_DIR, filename)
    loader = importlib.machinery.SourceFileLoader(module_name, path)
    spec = importlib.util.spec_from_loader(module_name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    loader.exec_module(module)
    _MODULE_CACHE[module_name] = module
    return module


def load_build(module_name, filename):
    """Load one build/ script as a module and return it.

    Kept separate from load_bin: the build helpers are not on the
    installed library path, and nothing here should drag bin/ngmap.py in
    behind them. They are also not registered in sys.modules, because
    only the caller imports them.
    """
    path = os.path.join(BUILD_DIR, filename)
    loader = importlib.machinery.SourceFileLoader(module_name, path)
    spec = importlib.util.spec_from_loader(module_name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def watchdog_anomaly_source():
    """Return the Python source of the watchdog's ANOMPY heredoc.

    Fails loudly rather than silently testing nothing when the markers are
    missing or ambiguous, which is what a reformat of the script would
    look like from here.
    """
    with open(WATCHDOG) as f:
        lines = f.read().splitlines()
    starts = [i for i, ln in enumerate(lines) if f"<<'{ANOM_MARKER}'" in ln]
    ends = [i for i, ln in enumerate(lines) if ln.strip() == ANOM_MARKER]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        raise AssertionError(
            f"{WATCHDOG}: expected exactly one {ANOM_MARKER} heredoc, found "
            f"{len(starts)} openers and {len(ends)} terminators")
    return "\n".join(lines[starts[0] + 1:ends[0]]) + "\n"


def patch_attrs(case, target, **attrs):
    """Set attributes on a module or object for one test, restoring the
    originals when it ends. The modules under test hold their absolute
    paths as module-level constants, so this is how a test points them at
    a temporary directory."""
    for name, value in attrs.items():
        original = getattr(target, name)
        case.addCleanup(setattr, target, name, original)
        setattr(target, name, value)


def patch_env(case, **variables):
    """Set environment variables for one test, restoring the previous
    values (or absence) when it ends."""
    for name, value in variables.items():
        original = os.environ.get(name)
        if original is None:
            case.addCleanup(os.environ.pop, name, None)
        else:
            case.addCleanup(os.environ.__setitem__, name, original)
        os.environ[name] = value


def temp_dir(case):
    """Create a temporary directory removed when the test ends."""
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    return tmp.name


@contextlib.contextmanager
def captured_log():
    """Capture what the code under test writes to stdout, which is where
    every module under test logs."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


@contextlib.contextmanager
def captured_error():
    """Capture what the code under test writes to stderr, which is where
    the CLI's diagnostics go."""
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        yield buf


def run_main(module, argv):
    """Run a module's CLI entry point with argv and return
    (exit_code, stdout, stderr). Exit code 0 means main() returned or
    exited cleanly; this is the level the operator-facing diagnostics are
    asserted at."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    saved_argv = sys.argv
    sys.argv = [module.__name__] + list(argv)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            module.main()
    except SystemExit as e:
        if e.code is None:
            code = 0
        elif isinstance(e.code, int):
            code = e.code
        else:
            code = 1
    finally:
        sys.argv = saved_argv
    return code, out.getvalue(), err.getvalue()


class FakeMaps:
    """In-memory stand-in for the pinned BPF maps.

    Encodes the contract ngmap's callers depend on, not bpftool's
    behaviour: a lookup miss reads as None, and deleting an absent key
    reports False rather than raising. The real bpftool semantics are
    guarded by the netns rehearsal in build/build.sh, where a real
    bpftool exists.
    """

    def __init__(self, allow=()):
        """Start with empty maps and an optional live allowlist."""
        self.maps = {}
        self.allow = list(allow)
        self.updates = []
        self.deletes = []

    def update_map(self, path, key, value):
        """Insert or overwrite one entry, recording the call."""
        self.maps.setdefault(path, {})[bytes(key)] = bytes(value)
        self.updates.append((path, bytes(key), bytes(value)))

    def lookup_value(self, path, key):
        """Value bytes for one key, or None if absent."""
        return self.maps.get(path, {}).get(bytes(key))

    def delete_key(self, path, key):
        """Delete one entry, reporting False when the key was already
        gone, which is the tolerated case in the real helper."""
        self.deletes.append((path, bytes(key)))
        return self.maps.get(path, {}).pop(bytes(key), None) is not None

    def dump_map(self, path):
        """Yield (key, value) for each entry; an unknown map is empty."""
        for key, value in list(self.maps.get(path, {}).items()):
            yield key, value

    def allow_entries_live(self):
        """Return the networks the fake allow maps hold."""
        return list(self.allow)

    def install(self, case, ngmap):
        """Patch the fake over ngmap's map helpers for one test, and point
        the block lock at a temporary file so the real lock discipline
        still executes."""
        patch_attrs(case, ngmap,
                    update_map=self.update_map,
                    lookup_value=self.lookup_value,
                    delete_key=self.delete_key,
                    dump_map=self.dump_map,
                    allow_entries_live=self.allow_entries_live,
                    BLOCK_LOCK=os.path.join(temp_dir(case), "block.lock"))
