#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for bin/nodeguard-feeds fetch(): feed bodies are accepted
over https only (evaluation finding S5).

urllib follows redirects across schemes, so a feed configured as https
can still deliver its body in cleartext. The transport is stubbed, so
these tests issue no request of any kind.
"""

import unittest

import ngtest

feeds = ngtest.load_bin("nodeguard_feeds", "nodeguard-feeds")

FEED = "spamhaus_drop_v4"
HTTPS_URL = "https://example.invalid/drop_v4.json"
HTTPS_MIRROR_URL = "https://mirror.example.invalid/drop_v4.json"
HTTP_URL = "http://mirror.example.invalid/drop_v4.json"
BODY = b'{"cidr": "203.0.113.0/24"}\n'
MAX_BYTES = 4194304
ETAG = '"abc123"'
LAST_MODIFIED = "Sat, 06 Sep 2026 00:00:00 GMT"


class FakeResponse:
    """The three things fetch() asks a urlopen result for: the URL the
    request actually landed on, the body, and the caching headers."""

    def __init__(self, final_url, body):
        self.final_url = final_url
        self.body = body
        self.headers = {"ETag": ETAG, "Last-Modified": LAST_MODIFIED}

    def geturl(self):
        """The post-redirect URL, which is the only honest answer to
        where the body came from."""
        return self.final_url

    def read(self, size):
        """Return the canned body, honoring fetch()'s byte cap read."""
        return self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class FakeOpener:
    """Recording stand-in for urllib.request.urlopen."""

    def __init__(self, final_url, body=BODY):
        self.response = FakeResponse(final_url, body)
        self.requests = []

    def urlopen(self, req, **_kwargs):
        """Record the request and hand back the canned response."""
        self.requests.append(req)
        return self.response


class FetchSchemeTest(unittest.TestCase):
    """Where the body came from decides whether it is read at all."""

    def setUp(self):
        self.meta = {"etag": ETAG, "last_modified": LAST_MODIFIED}
        self.set_url(HTTPS_URL)

    def set_url(self, url):
        """Point the feed definition at one URL for this test."""
        defs = dict(feeds.FEED_DEFS)
        defs[FEED] = dict(defs[FEED], url=url)
        ngtest.patch_attrs(self, feeds, FEED_DEFS=defs)

    def install(self, opener):
        """Patch the stub over urllib's opener for this test."""
        ngtest.patch_attrs(self, feeds.urllib.request, urlopen=opener.urlopen)
        return opener

    def fetch(self):
        """Run one fetch of the feed under test."""
        return feeds.fetch(FEED, self.meta, MAX_BYTES)

    def test_same_scheme_redirect_still_succeeds(self):
        opener = self.install(FakeOpener(HTTPS_MIRROR_URL))

        status, body, hdrs = self.fetch()

        self.assertEqual(status, "ok")
        self.assertEqual(body, BODY)
        self.assertEqual(hdrs, {"etag": ETAG,
                                "last_modified": LAST_MODIFIED})
        self.assertEqual(len(opener.requests), 1)

    def test_redirect_to_cleartext_fails_the_feed(self):
        self.install(FakeOpener(HTTP_URL))

        status, body, hdrs = self.fetch()

        self.assertTrue(status.startswith("failed:"), status)
        self.assertIn(HTTP_URL, status)
        self.assertIsNone(body)
        # No conditional-GET state to persist: the caller writes etag and
        # last-modified from these headers only, and only after the body
        # has passed every validation gate.
        self.assertEqual(hdrs, {})
        self.assertEqual(self.meta, {"etag": ETAG,
                                     "last_modified": LAST_MODIFIED})

    def test_non_https_configured_url_never_leaves_the_host(self):
        self.set_url(HTTP_URL)
        opener = self.install(FakeOpener(HTTP_URL))

        status, body, hdrs = self.fetch()

        self.assertTrue(status.startswith("failed:"), status)
        self.assertIn(HTTP_URL, status)
        self.assertIsNone(body)
        self.assertEqual(hdrs, {})
        self.assertEqual(opener.requests, [])


class ShippedFeedDefsTest(unittest.TestCase):
    """The definitions as shipped, with nothing patched over them."""

    def test_every_shipped_feed_url_is_https(self):
        # The configured URLs are the half a code review can check; the
        # redirect check above is the half it cannot.
        for feed, definition in feeds.FEED_DEFS.items():
            with self.subTest(feed=feed):
                self.assertTrue(
                    definition["url"].startswith(feeds.FEED_SCHEME))


if __name__ == "__main__":
    unittest.main()
