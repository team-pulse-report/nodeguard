## ADDED Requirements

### Requirement: Deploy SHALL ship every repository executable a shipped unit invokes
deploy.sh SHALL stage, install, and syntax-verify every
repository-shipped executable referenced by any unit file it installs
(stock package binaries such as /usr/bin/suricata-update and
/usr/bin/python3 are explicitly out of scope), with Python executables
compiled via py_compile and shell executables checked via bash -n, and
the set of units verified SHALL be identical to the set of units
installed, both derived from a single shared source so the two cannot
diverge.

#### Scenario: geo binary ships with its timer
- WHEN deploy.sh installs nodeguard-geo.service and nodeguard-geo.timer
- THEN /usr/local/sbin/nodeguard-geo is installed in the same run and
  has passed py_compile, so the timer can never fire into 203/EXEC on a
  deploy.sh-built host

#### Scenario: verify list cannot diverge from the install list
- WHEN a new unit file is added to units/ and picked up by the staging
  step
- THEN the same shared unit list feeds both the install command and the
  systemd-analyze verification loop, so the new unit is installed and
  verified without any hand-edit to a second list

### Requirement: The kernel object SHALL be verified against its recorded sha256 before installation
When deploying kernel artifacts, deploy.sh SHALL verify the local
object against the build-emitted .sha256 before staging, SHALL compare
the staged object's recomputed hash on the remote side against the
build-recorded hash before any install step, and SHALL fail before the
.prev rotation on any mismatch; the .sha256 SHALL be installed beside
the object.

#### Scenario: stale build output is rejected locally
- WHEN build/out holds an object and a .sha256 written by different
  build runs (for example a stale checkout)
- THEN deploy.sh aborts before staging anything, and the host is not
  contacted with the mismatched object

#### Scenario: remote mismatch fails before rollback state is touched
- WHEN the staged object's recomputed hash differs from the expected
  hash passed into the remote script
- THEN the run fails before the .prev rotation and before any install,
  leaving the previous object, spec, and .prev untouched

### Requirement: Deploy verification SHALL run before installation and rollback state SHALL cover the object-spec pair
The deploy verification block SHALL run against staged copies before
the first install command (syntax checks, unit verification including
the per-host drop-in, content checks, hash comparison, and suricata -T
against the staged suricata.yaml on any host carrying a ruleset for it
to load), so a verification failure leaves the host unchanged; a check
that cannot run SHALL be reported as unvalidated rather than passed;
and nodeguard-maps.spec SHALL rotate to .prev together with the kernel
object under a single only-when-different decision taken over the pair,
so rollback restores a consistent object-spec pair.

#### Scenario: verification failure leaves the host untouched
- WHEN any verification step fails (a unit fails systemd-analyze
  verify, a script fails bash -n, suricata -T rejects the staged
  suricata.yaml)
- THEN the run exits nonzero with nothing installed, and the host's
  files are byte-identical to before the run

#### Scenario: first deploy to a bare host is not spuriously failed
- WHEN deploy.sh runs against a host where the /usr/local/sbin
  executables the staged units reference do not exist yet
- THEN unit verification runs over the staged unit copies with
  executable-existence diagnostics resolved against the staged set
  (those executables are syntax-verified in the same pre-install pass
  and installed by the same run), so the bootstrap deploy passes
  verification while a reference to a path this run does not ship
  still fails it

#### Scenario: the per-host drop-in is verified with the unit it modifies
- WHEN deploy.sh verifies the staged nodeguard-xdp.service
- THEN the per-host drop-in is staged in the <unit>.d directory beside
  it so systemd merges the two, and a malformed drop-in fails the
  deploy instead of installing silently and failing at boot

#### Scenario: suricata configuration is validated before it can go live
- WHEN a generated suricata.yaml that suricata would refuse is staged
  on a host whose ruleset is installed
- THEN suricata -T fails the verification block and the broken
  configuration is never installed over the working one

#### Scenario: a host with no ruleset yet reports unvalidated, not failed
- WHEN deploy.sh runs at phase 0, before suricata-update has ever
  written the ruleset the staged configuration names, so suricata -T
  would fail on the missing rule file rather than on the configuration
- THEN the deploy reports the staged suricata.yaml as unvalidated and
  names the reason, and the bootstrap deploy proceeds rather than
  aborting with nothing installed

#### Scenario: rollback restores object and spec together
- WHEN a --with-kernel deploy replaces a differing object and spec and
  the operator later rolls back, including after a sequence of deploys
  in which one changed only the object and a later one only the spec
- THEN both nodeguard_kern.o.prev and nodeguard-maps.spec.prev exist
  from the same pre-deploy state, so the restored pair passes the
  spec-object pairing check

### Requirement: Deploy SHALL surface suricata stock-config drift
deploy.sh SHALL compare the host's installed suricata RPM version
against the recorded stock source version shipped with the artifacts,
and SHALL check for a suricata.yaml.rpmnew on the host, reporting
either condition loudly in the deploy output.

#### Scenario: host RPM has moved past the recorded stock version
- WHEN the host's installed suricata NVR (queried arch-free, so the
  architecture suffix cannot fabricate a permanent mismatch) differs
  from the recorded stock source version
- THEN the deploy output carries an explicit drift warning naming both
  versions, so a stock refresh can be scheduled instead of the drift
  accumulating silently

#### Scenario: an rpmnew is flagged instead of ignored
- WHEN /etc/suricata/suricata.yaml.rpmnew exists on the host
- THEN the deploy output warns that the RPM shipped a config schema the
  generated file has not been reconciled against
