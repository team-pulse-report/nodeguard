# fix-nodeguard-deploy-reliability: design

Source: the 2026-09-06 evaluation report, findings R1, R2, R3, B1, B2,
B3, B4, B5, including the refuter corrections embedded in each finding.
Every claim below was re-verified against the tree on 2026-09-06.

## 1. Oneshot timeouts (R1)

systemd's DefaultTimeoutStartSec does not apply to Type=oneshot
services; their start timeout defaults to infinity. Every timer-driven
unit in this repository is a bare oneshot with no TimeoutStartSec:
units/nodeguard-watchdog.service:5, units/nodeguard-sweep.service:5,
units/nodeguard-geo.service:6, units/nodeguard-feeds.service:7,
units/suricata-update.service:7. The boot-path oneshots
units/nodeguard-maps.service:7 and units/nodeguard-xdp.service:8
(RemainAfterExit=yes) have the same gap.

A blocking call inside a cycle (a wedged tailscaled is a known event on
these hosts; a stuck xdp-loader) leaves the oneshot in activating
forever, and a timer whose service is still activating does not fire
again: no canary or lifeline soft-off, no WG port refresh, no kv
snapshot, no auto re-arm. Zabbix catches the frozen kv externally in 5
to 6 minutes (the fuzzytime trigger on ng.ts targets exactly this), but
the host keeps enforcing with no over-block protection until a human
acts.

Decision: TimeoutStartSec on every Type=oneshot unit, sized below the
unit's own timer period so a killed cycle is retried on the next fire:

| unit | timer period | TimeoutStartSec |
|---|---|---|
| nodeguard-watchdog | 1min (units/nodeguard-watchdog.timer) | 55s |
| nodeguard-sweep | 10min (units/nodeguard-sweep.timer) | 8min |
| nodeguard-geo | 5min (units/nodeguard-geo.timer) | 4min |
| nodeguard-feeds | 6h (units/nodeguard-feeds.timer) | 30min |
| suricata-update | daily (units/suricata-update.timer) | 30min |
| nodeguard-maps | boot path | 2min |
| nodeguard-xdp | boot path | 2min |

The boot-path values are generous: nodeguard-maps recreates pins and
loads allowlists in seconds, and nodeguard-attach's slowest path is the
ixgbe attach blip plus the identity check. A bounded failure that lands
the unit in failed (where the existing unit alarms see it) is strictly
better than activating forever (where nothing does).

Secondary hardening: the scripts these units run still contain untimed
external calls (bin/nodeguard-watchdog shells out to tailscale and
xdp-loader without timeout(1); bin/nodeguard-geo already bounds its
bpftool dump with timeout=30 at bin/nodeguard-geo:56). The sweep in
task 1.3 wraps the remaining untimed calls so a single wedged tool
fails one step instead of eating the whole timeout budget. The
watchdog's untimed xdp-loader call does not live in
bin/nodeguard-watchdog itself: it lives in ng_prog_ids at
bin/nodeguard-lib.sh:42-51, shared by watchdog, status, attach,
detach, and reload. The timeout wrapper for that call therefore lands
inside ng_prog_ids, and it MUST preserve the helper's three-valued rc
contract that section 3 depends on: a timeout(1) expiry surfaces as a
nonzero rc with a logged error, which callers already treat as state
UNKNOWN. bin/nodeguard-lib.sh joins the affected-code list for this
reason.

The bpftool bound in bin/ngmap.py cannot be one number, because the same
file serves the sweep (8min budget, whole-map dumps) and the watchdog
cycle (55s budget, many calls in a row: three ng_cfg_get reads of its
own plus the three reads and two dumps nodeguard-status --kv makes).
Sized for the loose consumer it rides the tight unit's timeout on the
second wedged call; sized for the tight one it fails a slow but working
dump. The default therefore stays 30s and ngmap.py reads an
NG_BPFTOOL_TIMEOUT override, which bin/nodeguard-watchdog exports as
NG_TOOL_TIMEOUT (10s, the shell-side bound) so every ngmap child it
spawns, directly or through nodeguard-status, inherits the tight value
from the one definition in bin/nodeguard-lib.sh. An unusable override
falls back to the default rather than raising, since the read happens at
import and a typo must not take every map operation on the host down.

Documentation correction (refuter, carried with R1): the failure-mode
table row at docs/design.md:482 reads "Watchdog itself dead | No latch
protection; datapath unchanged | Timer unit alarm". For a crashed
watchdog that is right; for a HUNG one it is wrong, because the timer
whose service is stuck activating stops firing and no timer alarm
exists. The cell is corrected to name TimeoutStartSec as the mechanism
that converts a hang into the visible failed state.

## 2. deploy.sh ships the geo timer without its binary (R2)

deploy/deploy.sh installs every unit by glob (deploy/deploy.sh:105
installs "$S"/nodeguard-*.service "$S"/nodeguard-*.timer), which
includes nodeguard-geo.service and nodeguard-geo.timer, but:

- the scp list (deploy/deploy.sh:52-58) names every bin/ executable
  except bin/nodeguard-geo;
- the sbin install loop (deploy/deploy.sh:93-97) omits nodeguard-geo;
- the verification block compiles the three Python executables at
  deploy/deploy.sh:147 and nodeguard-geo is not among them;
- the systemd-analyze verify list (deploy/deploy.sh:149-152) is a
  hand-maintained eleven-unit list that also omits nodeguard-geo's
  unit and timer, which is exactly how the divergence went unnoticed.

Result on a deploy.sh-built host: a timer firing every 5 minutes into
203/EXEC forever. geo.kv never appears, and nodeguard-status treats a
missing geo.kv as "absent until the first run", so the dashboards'
geography telemetry is silently missing rather than alarmed. This is
the same failure class as the 203/EXEC transient-unit bug already
recorded in the head folder's AGENTS.md provenance.

Decision, honoring the refuter corrections:

1. Add bin/nodeguard-geo to the scp list and the sbin install loop.
2. nodeguard-geo is Python (bin/nodeguard-geo:1 is a python3
   shebang), so it joins the py_compile line at deploy/deploy.sh:147,
   not the bash -n loop.
3. Replace the hand-maintained verify list with one derived from the
   same source that installs units. The current install line
   (deploy/deploy.sh:105-106) is itself two expressions:
   "$S"/nodeguard-*.service "$S"/nodeguard-*.timer plus the two
   explicitly named suricata-update files, so deriving the verify list
   from a bare "$S"/*.service "$S"/*.timer glob while the install line
   stays nodeguard-* would just create a second divergence (a future
   non-nodeguard-prefixed unit verified but not installed, or the
   reverse). The fix is one definition consumed by both steps: the
   heredoc materializes the staged unit list once (a single glob
   expansion into a shell array or variable), the install command
   installs exactly that list, and the verify loop iterates the same
   list. Install set and verify set become identical by construction.

## 3. Detach and attach absorb ng_prog_ids failures (R3)

ng_prog_ids (bin/nodeguard-lib.sh:42-51) has a three-valued contract:
ids on stdout (attached), empty output with rc 0 (not attached), or
nonzero rc with a logged error (state UNKNOWN, xdp-loader itself
failed). Two call sites in nodeguard-detach and one in nodeguard-attach
collapse UNKNOWN into "not attached":

- bin/nodeguard-detach:15: live=$(ng_prog_ids) drops the rc; a loader
  failure yields empty ids, the empty-list branch at
  bin/nodeguard-detach:18-21 logs "nothing to detach", deletes
  prog_id and expected_prog_id, and exits 0.
- bin/nodeguard-detach:30: the unload-failure recheck pipes
  ng_prog_ids through grep -qx. The script runs under set -uo
  pipefail (bin/nodeguard-detach:4), so a failed ng_prog_ids does
  propagate into the pipeline status; but the pipeline is nonzero both
  when the id is genuinely gone (ng_prog_ids succeeded, grep found no
  match) and when the loader itself failed (ng_prog_ids printed
  nothing, grep found no match), and the if-condition treats any
  nonzero status as "id no longer live". A loader failure therefore
  reads as a clean unload, after which bin/nodeguard-detach:36
  deletes the run files. Capturing output and rc separately is what
  restores the distinction.
- bin/nodeguard-attach:12: existing=$(ng_prog_ids) || existing=""
  explicitly absorbs the failure and proceeds as if no member exists.

During an over-block incident, systemctl stop nodeguard-xdp (whose
ExecStop is nodeguard-detach, units/nodeguard-xdp.service:11) reports
success while the program keeps dropping: the dangerous direction for a
fail-open design. The damage is mitigated by nodeguard-off working
through the pinned map, but the evidence chain for ng.prog_match is
destroyed because expected_prog_id was deleted on a lie.

Decision: capture the rc at all three sites. In detach, on a nonzero
ng_prog_ids rc at either the initial listing (line 15) or the unload
recheck (line 30), log "attach state UNKNOWN, refusing to report clean
detach", exit nonzero, and delete no run files. The recheck stops
piping directly: capture output and rc first, then grep the captured
output. In attach, a nonzero rc at the initial listing fails the attach
loudly (the host runs OPEN and says so, matching the existing failure
style at bin/nodeguard-attach:38).

## 4. The sha256 is never verified (B1)

build/build.sh:291 writes build/out/nodeguard_kern.o.sha256, and ADR
0004 (docs/adr/0004-map-spec-generated-from-object.md:58-59) calls the
emitted sha256 "the pairing evidence"; but deploy/deploy.sh:165 merely
prints sha256sum of the installed object for a human to eyeball. The
.sha256 file is never shipped, never read at load time, and compared
against nothing.

Refuter correction, adopted as the threat model: an interrupted scp
cannot cause a mismatch, because set -euo pipefail
(deploy/deploy.sh:11) aborts the run first. The real scenario is a
stale build/out from a different checkout: object and .sha256 written
by different build runs, or an object rebuilt while the operator
deploys an older tree.

Decision:

1. Before staging, deploy.sh verifies build/out/nodeguard_kern.o
   against build/out/nodeguard_kern.o.sha256 locally (sha256sum -c
   with the filename path adjusted) and aborts on mismatch or missing
   .sha256 when --with-kernel is given.
2. The expected hash is interpolated into the remote heredoc, and the
   remote side recomputes the staged object's hash and compares before
   any install step, so the check fails before the .prev rotation at
   deploy/deploy.sh:85-88 can run.
3. The .sha256 file is installed beside the object under
   /usr/local/lib/nodeguard/ so a later change can teach
   nodeguard-attach to assert it at load time (recorded as optional
   follow-up, not implemented here).

## 5. Build provenance (B2)

The build runs in a floating image (README.md:53 and build/build.sh:7
both say fedora:44 with no digest) and installs clang, llvm, libbpf,
xdp-tools, and bpftool unpinned at build/build.sh:16-17. Nothing
records what produced build/out/nodeguard_kern.o, so during an incident
"did the source change or just the compiler" is undecidable.

Decision: record provenance, do not claim reproducibility.

1. build.sh writes build/out/nodeguard_kern.o.buildinfo beside the
   object: clang --version, rpm -q NVRs for clang llvm libbpf-devel
   libxdp-devel xdp-tools bpftool kernel-headers, the repo git commit
   (git -C /work rev-parse HEAD, recorded as unknown if the mount has
   no .git). Two things have to be arranged for that field to ever hold
   a commit, and without them it reads unknown on every build rather
   than only on a .git-less mount: the fedora:44 base image ships no
   git, so build.sh installs it (outside TOOLCHAIN_PKGS, since git does
   not reach the object), and /work is a bind mount owned by the host
   uid while the container runs as root, so git rejects the checkout as
   dubious ownership until the path is registered in safe.directory.
   The buildinfo also carries the base image digest from the
   IMAGE_DIGEST environment
   variable passed by the runner (recorded as unknown when unset; the
   digest is not discoverable from inside a plain docker run, so the
   host must resolve and pass it), and the build UTC timestamp.
2. README gains guidance to pin the builder invocation by digest and
   to populate the buildinfo digest field, showing the working
   pattern: resolve on the host with
   docker inspect --format '{{index .RepoDigests 0}}' fedora:44,
   pass it as -e IMAGE_DIGEST="...", and run fedora@sha256:... as the
   image reference. The digest is refreshed deliberately, with the
   buildinfo file as the audit trail; the rpm NVRs remain the
   fallback provenance when the operator skips the pin.
3. Explicit non-goal: bit-reproducibility. Two builds from the same
   commit may differ; the buildinfo file exists so the difference is
   explainable.

## 6. deploy verifies after installing; spec has no .prev; no suricata -T (B3)

The verification block at deploy/deploy.sh:139-164 runs after every
install call (deploy/deploy.sh:79-137), so a verification failure exits
4 with the new files already live and nothing to roll back to. Only the
kernel object keeps an N-1 copy (deploy/deploy.sh:85-88); the map spec
it is paired with does not, so a hitless rollback of a mis-paired
deploy is blocked (the refuter confirmed the spec check catches
mis-pairs loudly, so the cost is a blocked rollback, not silent
mis-pairing). And build/mkyaml.py:5 plus build/mkyaml.py:41 both
promise the generated suricata.yaml "is validated on-host with
suricata -T", which no code anywhere runs.

Decision:

1. Reorder the remote heredoc: run bash -n, py_compile,
   systemd-analyze verify (over the staged unit copies, using the
   shared list from section 2), the zabbix and logrotate content
   greps, the sha256 comparison from section 4, the stock-version
   check from section 7, and suricata -T against the staged
   suricata.yaml, all against files under $S, before the first
   install command. A verification failure leaves the host
   byte-identical to before the run.

   The unit verification step needs one accommodation that a naive
   reorder misses: systemd-analyze verify checks that ExecStart
   binaries exist on the filesystem. On a first-ever deploy to a bare
   host (a supported flow; the phase-0 preflight at deploy/deploy.sh:77
   exists exactly for it) the staged units reference
   /usr/local/sbin/nodeguard-* paths that do not exist yet, so a naive
   pre-install verify fails spuriously; and on an upgrade deploy it
   would silently check against the OLD installed binaries rather
   than the staged ones. The verify step therefore filters
   executable-existence diagnostics for exactly those ExecStart and
   ExecStop paths that this run installs: the path must sit under one
   of the two destinations the install loop writes to
   (/usr/local/sbin or /usr/local/lib/nodeguard) AND its basename must
   be present in the staging directory. Those executables are
   syntax-verified separately (bash -n, py_compile, also pre-install)
   and are installed by this same run, so their absence or staleness on
   disk is not a defect of the staged unit. The destination test is not
   redundant with the basename test: a unit whose ExecStart named
   /usr/bin/nodeguard-geo, a path no run installs, would otherwise be
   filtered by the staged file of the same name and its 203/EXEC
   shipped silently, which is the exact failure this change exists to
   stop. Diagnostics for any other path, and all non-existence
   diagnostics, still fail verification. This keeps both properties:
   the bootstrap deploy passes, and no install command runs before
   verification completes, so a failure still leaves the host
   untouched.

   The per-host drop-in is verified with the unit it modifies. Before
   the loop, the staged flat nodeguard-xdp-10-device.conf is copied to
   "$S"/nodeguard-xdp.service.d/10-device.conf and installed from
   there, because systemd merges drop-ins from a <unit>.d directory
   beside the unit file and merges nothing into a flat neighbour. The
   old post-install loop verified /etc/systemd/system/<unit>, where the
   installed drop-in was already merged; without this the one fragment
   that changes per host (it carries the Wants= and After= on the
   interface's .device unit) would become the only unit fragment
   nothing verifies. The copy rearranges the staging directory only and
   the "$S"/*.service glob does not match the .d directory, so the
   shared unit list is unchanged.
2. suricata -T runs as suricata -T -c "$S/suricata.yaml" with the
   host's rule paths; its nonzero exit sets verify_fail like the
   existing checks, but ONLY when the host has a ruleset. suricata -T
   forces engine.init-failure-fatal, and the generated yaml carries
   default-rule-path /var/lib/suricata/rules with rule-files
   suricata.rules, a file no suricata RPM creates: it appears when
   suricata-update first runs, which is phase 1 (docs/design.md
   section 6.4), one phase AFTER the deploy. An unconditional gate
   therefore aborts every phase-0 bootstrap with exit 4 and installs
   nothing, defeating the flow item 1 above is written to preserve. The
   ruleset gates the check instead: absent, the deploy prints that the
   staged yaml is UNVALIDATED and why, and proceeds. A skipped
   validation is reported as unknown, never as a pass.
3. nodeguard-maps.spec rotates to .prev together with the object, under
   one only-when-different decision taken over the pair rather than a
   guard per artifact (deploy/deploy.sh:85-88 held the object's). A
   per-artifact guard rotates whichever file changed and leaves the
   other at an older generation, so a deploy that changes only the
   object followed by one that changes only the spec (which the spec
   generator changing produces) leaves a straddled .prev pair that the
   spec-object pairing check then refuses: a blocked rollback, arrived
   at through the mechanism meant to enable it. One decision, both
   files, so rollback restores a pair that actually coexisted.

## 7. install-geoip NameError (B4) and stock drift (B5)

B4: build/install-geoip.sh:53 is
print(f"geoip index built: {n} ranges ({MONTH})".replace(...)). The
heredoc is quoted ('PYEOF', build/install-geoip.sh:23), so {MONTH}
reaches Python literally and the f-string evaluates it as an undefined
Python name: NameError on every successful run. The index still
installs because os.replace at build/install-geoip.sh:49-52 precedes
the print, but every run emits a traceback and the range count is
lost. Fix per the report: pass the month into the embedded Python as
argv, like the src and share parameters at build/install-geoip.sh:25,
and drop the .replace hack.

B5: build/mkyaml.py:128 hardcodes "suricata-8.0.6-1.fc44" in the
generated header, and nothing checks that build/suricata-stock.yaml
still matches the RPM installed on the hosts or flags a
suricata.yaml.rpmnew left by an RPM update. A hard suricata failure
would alarm through the existing triggers; silent config degradation
and a provenance lie in every generated header would not.

Decision:

1. New committed sidecar build/suricata-stock.version holding the
   exact NVR the stock file was captured from (initial content
   suricata-8.0.6-1.fc44). mkyaml.py reads it and renders the header
   from it; build.sh fails if the sidecar is missing. Whoever
   refreshes suricata-stock.yaml must update the sidecar in the same
   commit, and the header stops lying by construction.
2. deploy.sh ships the sidecar and, in the pre-install verification
   block, compares the host's installed suricata NVR against it, and
   checks for /etc/suricata/suricata.yaml.rpmnew. The query is
   arch-free: rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' suricata,
   because plain rpm -q prints the arch-qualified NVRA
   (suricata-8.0.6-1.fc44.x86_64) and a naive compare against the
   sidecar's suricata-8.0.6-1.fc44 would warn on every deploy,
   training operators to ignore the warning. Both checks report
   loudly; drift
   is a warning line (deploy proceeds, since a newer host RPM with an
   unchanged config schema is common), while the .rpmnew check also
   warns, matching the existing logrotate .rpmnew handling at
   deploy/deploy.sh:133 which deletes only the file deploy itself
   owns.

## 8. Local verification (scope)

Everything in this change is verifiable off-host: bash -n and
shellcheck on the touched shell scripts, python3 -m py_compile on
mkyaml.py and nodeguard-geo, a fixture run of install-geoip.sh's
embedded preprocessor proving the summary line prints without a
traceback, a local execution of the glob-derivation snippet against
units/, unit tests for mkyaml.py's sidecar handling, and openspec
validate --strict. Deployment to devops-hive-node-2 and node-3 is the
human follow-up recorded in proposal.md; no task below touches a host.
