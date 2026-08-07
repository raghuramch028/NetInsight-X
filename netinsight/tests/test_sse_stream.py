"""Tests for the async SSE live-metrics stream (api_stream_metrics).

Regression context: this endpoint previously blocked a whole OS thread/process for its entire
connection lifetime on a synchronous WSGI view (a `while True: ... time.sleep(1.0)` generator).
It's now a genuine `async def` Django view so that under an ASGI server, a connection parks on
`await asyncio.sleep(1.0)` instead of pinning a thread. These tests verify it still produces
correct output, still respects the dashboard auth gate, and still bounds concurrency/duration —
all of which had to keep working across the sync -> async conversion.
"""
import asyncio
import json
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")

import django

django.setup()

from django.test import AsyncClient, Client, TestCase
from django.urls import reverse

from netinsight.config import settings
from netinsight.dashboard.views import api_views


class TestSSEStreamAsync(TestCase):

    async def _get_first_event(self, response):
        """Reads exactly one SSE event from the async streaming response, then closes the
        generator so its `finally: _sse_semaphore.release()` runs — without this, the semaphore
        permit leaks for the lifetime of the test process, since the generator otherwise never
        reaches its `finally` block on its own (it's an infinite loop)."""
        agen = response.streaming_content
        chunk = await asyncio.wait_for(agen.__anext__(), timeout=5.0)
        await agen.aclose()
        return chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

    async def test_stream_yields_valid_sse_payload(self):
        client = AsyncClient()
        response = await client.get(reverse("dashboard:api_stream_metrics"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/event-stream")

        text = await self._get_first_event(response)
        self.assertTrue(text.startswith("data: "))
        payload = json.loads(text[len("data: "):].strip())
        self.assertIn("network_state", payload)
        self.assertIn("mdp_recommendation", payload)

    async def test_stream_respects_connection_cap(self):
        """Exhausting the semaphore must return 503 instead of hanging/blocking."""
        acquired = 0
        try:
            while api_views._sse_semaphore.acquire(blocking=False):
                acquired += 1

            client = AsyncClient()
            response = await client.get(reverse("dashboard:api_stream_metrics"))
            self.assertEqual(response.status_code, 503)
        finally:
            for _ in range(acquired):
                api_views._sse_semaphore.release()

    async def test_stream_blocked_when_dashboard_auth_required(self):
        original = getattr(settings, "NETINSIGHT_REQUIRE_AUTH", False)
        try:
            settings.NETINSIGHT_REQUIRE_AUTH = True
            client = AsyncClient()
            response = await client.get(reverse("dashboard:api_stream_metrics"))
            self.assertEqual(response.status_code, 401)
        finally:
            settings.NETINSIGHT_REQUIRE_AUTH = original

    def test_stream_reachable_via_sync_test_client_too(self):
        """Django adapts async views for sync callers automatically (via AsyncToSync, which
        requires NOT already being inside a running event loop — hence this is a plain sync
        test method, not `async def` like the others). The ordinary (sync) test Client hitting
        this URL must not raise, mirroring how a plain WSGI deployment (the safe fallback
        documented in README) still serves this endpoint correctly."""
        client = Client()
        response = client.get(reverse("dashboard:api_stream_metrics"))
        self.assertEqual(response.status_code, 200)
        # response.streaming_content is still the raw async generator even via the sync Client —
        # close it properly so its `finally: _sse_semaphore.release()` runs.
        asyncio.run(response.streaming_content.aclose())
