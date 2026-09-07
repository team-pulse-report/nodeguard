# xdp-enforcement Specification

## Purpose

The datapath contract: what the XDP program and the tooling that writes
its maps must guarantee about which packets are dropped. Requirements
here are being filled in by change add-nodeguard-firewall, which owns
the kernel-side enforcement, allowlist ordering, and kill-switch
behaviour; the map CLI's operator-input contract landed ahead of it.

## Requirements

### Requirement: The map CLI SHALL refuse out-of-range integers with a clean diagnostic
The map-management CLI SHALL validate every operator-supplied integer
against the range its packed map encoding can represent before any
encode or map operation, and SHALL refuse an out-of-range slot, value,
or TTL through its single diagnostic failure path (a one-line error
naming the offending value and the permitted range, nonzero exit). No
operator invocation SHALL ever terminate with a raw encoding
traceback; the entry point SHALL convert a packing error from any
residual site into the same diagnostic failure path.

#### Scenario: out-of-range config slot or value
- WHEN set-config is invoked with a negative slot, a negative value,
  or a value at or above 2^64
- THEN the command exits nonzero with a one-line diagnostic naming the
  offending value and the permitted range, writes nothing to any map,
  and prints no traceback

#### Scenario: kill-switch invocation during an incident stays clean
- WHEN an operator mistypes a set-config argument while latching or
  releasing the kill switch
- THEN the failure output is the tool's normal one-line error, so the
  operator can correct the command without parsing a stack trace

#### Scenario: oversized block TTL
- WHEN block is invoked with a --ttl large enough that the computed
  expiry cannot be represented in the 64-bit map value
- THEN the command refuses with a diagnostic phrased in terms of the
  --ttl argument and writes nothing to any map

#### Scenario: packing errors are converted at the entry point
- WHEN any remaining code path raises the encoding library's packing
  error during a CLI invocation
- THEN the entry point converts it to the standard diagnostic failure
  path with a nonzero exit instead of a traceback
