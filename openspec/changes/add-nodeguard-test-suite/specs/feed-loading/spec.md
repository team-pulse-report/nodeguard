## ADDED Requirements

### Requirement: A hostile feed body SHALL fail only its own feed
Any exception raised by a feed parser or by per-feed validation while
processing a fetched body SHALL fail that one feed through the normal
FAILED path (recorded in the diff, body preserved for inspection,
entries left to age out by TTL) and SHALL NOT terminate the run or
affect any other feed. A body whose cidr or records fields are not the
expected types SHALL be rejected as a validation failure of that feed,
never silently accepted as a bogus network and never permitted to
select an exception class the per-feed handler does not contain. This
requirement governs the per-feed parse and validation boundary only:
the run-level content gates (canary coverage, entry caps, coverage
caps, churn brake) continue to abort the affected feed or run per the
existing anomalous-content requirement.

#### Scenario: non-numeric records trailer
- WHEN a syntactically valid Spamhaus JSONL body arrives whose
  metadata trailer carries a records field that is not an integer (a
  string, list, null, or boolean)
- THEN that feed alone is FAILED for the run with a validation
  message, the offending body is saved for inspection, and every other
  configured feed completes normally

#### Scenario: cidr field of the wrong type
- WHEN a Spamhaus record line carries a cidr field that is not a
  string (for example a JSON integer or boolean, which the address
  parser would otherwise silently accept as a bogus /32 network)
- THEN that feed is FAILED for the run with a validation message and
  no entry derived from the wrong-typed field is planned or written

#### Scenario: parser raises an unanticipated exception class
- WHEN a feed body causes the parser to raise an exception outside the
  anticipated validation classes
- THEN the exception is contained at the per-feed boundary exactly as
  a validation failure is: the feed is FAILED, the run continues, and
  the run exits with its normal per-feed failure reporting

### Requirement: An unexpected run crash SHALL NOT arm crash-adoption from remote content
The loader SHALL clear its run-in-progress marker before exiting
nonzero when an unexpected exception escapes a run that has performed
no map write, so remote content can never arm crash-adoption mode; a
run that has already written map entries SHALL leave the marker set,
preserving bounded crash-adoption as the recovery for a genuine
mid-write crash.

#### Scenario: unexpected crash before any write
- WHEN an unexpected exception escapes the run loop after the
  run-in-progress marker was set but before any map mutation occurred
- THEN the marker is cleared, the diff and metrics still land so the
  failure alarms, the process exits nonzero, and the next run reports
  no crash-adoption mode

#### Scenario: unexpected crash after writes preserves recovery
- WHEN an unexpected exception escapes the run loop after at least one
  map mutation was performed
- THEN the run-in-progress marker remains set and the next same-boot
  run enters bounded crash-adoption mode as designed
