# build-provenance Specification

## Purpose

What is recorded about how a shipped kernel artifact was produced, so a
deployed object can be traced back to the source, toolchain, and base
image that built it. This capability covers provenance, not
reproducibility: two builds of one commit may differ byte for byte, and
the point is that such a difference is explainable rather than a
mystery during an incident.

## Requirements

### Requirement: The build SHALL record toolchain provenance beside every kernel artifact
build.sh SHALL write a build-info file into build/out beside the
compiled object recording the clang version, the installed toolchain
package NVRs, the repository git commit, the base image digest, and the
build timestamp, with any value it cannot determine recorded explicitly
as unknown rather than omitted; this records provenance and SHALL NOT
be read as a bit-reproducibility guarantee.

#### Scenario: an incident can separate source change from toolchain change
- WHEN two builds of the same source produce differing objects
- THEN the two build-info files identify whether the clang version,
  package NVRs, base image, or git commit differed, so "did the source
  change or just the compiler" is decidable from build/out alone

#### Scenario: the commit field carries a commit rather than a permanent unknown
- WHEN the build runs the documented container invocation against the
  repository bind mount
- THEN the build environment provides git and treats the mounted
  checkout as a trusted one, so git_commit records the commit instead
  of degrading to unknown on every build and leaving the field
  worthless to the incident it exists for

#### Scenario: missing provenance is visible, not silent
- WHEN the container cannot determine the base image digest or the repo
  mount has no git metadata
- THEN the build-info file carries the literal value unknown for that
  field and the build still succeeds

### Requirement: The geoip index build SHALL complete without raising and SHALL report its result
install-geoip.sh SHALL pass the fetch month into its embedded
preprocessor as an argument, and a successful preprocessing run SHALL
print the built range count and month and exit cleanly with no
traceback.

#### Scenario: successful run reports instead of crashing
- WHEN the preprocessor finishes writing dbip.starts and dbip.recs
- THEN it prints the range count with the month it was built from, no
  NameError or traceback is emitted, and the exit status is zero

### Requirement: The generated suricata.yaml header SHALL derive its stock version from a committed sidecar
The stock suricata source version SHALL live in a committed sidecar
file beside the stock yaml; mkyaml.py SHALL read the sidecar to render
the generated header and SHALL fail when the sidecar is missing, so a
stock refresh that forgets the sidecar cannot produce a header carrying
a stale version.

#### Scenario: header follows the sidecar
- WHEN the stock yaml is refreshed from a newer RPM and the sidecar is
  updated in the same commit
- THEN every subsequently generated suricata.yaml header names the new
  version with no edit to mkyaml.py

#### Scenario: missing sidecar fails the build
- WHEN mkyaml.py runs with the sidecar absent
- THEN it exits nonzero naming the missing file, and build.sh fails
  rather than emitting a header with an unverifiable version
