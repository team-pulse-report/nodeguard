# feed-loading Specification (delta)

## ADDED Requirements

### Requirement: Feed bodies SHALL be accepted over https only
The loader SHALL fetch feeds only from https URLs and SHALL discard any
response whose final URL, after following any redirects, is not https;
the discard SHALL fail that one feed through the normal failed path,
with zero writes, zero withdrawals, and no conditional-GET state
persisted, while other feeds proceed.

#### Scenario: an upstream redirect to cleartext is refused
- WHEN a configured https feed URL answers with a redirect chain whose
  final hop is an http or other non-https URL
- THEN the body is discarded without being parsed, the feed is recorded
  failed with a status naming the non-https final URL, its existing
  entries age out by TTL only, and the failure surfaces through the
  existing per-feed staleness alerting if it persists

#### Scenario: a non-https configured URL never leaves the host
- WHEN a feed definition carries a URL whose scheme is not https
- THEN the loader refuses the feed before issuing any request and
  records it failed for the run
