"""Tests for the async SSE live-metrics stream (api_stream_metrics)."""
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
        self.assertIn("throughput", payload)
        self.assertIn("bandwidth_util", payload)

    async def test_stream_respects_connection_cap(self):
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
        client = Client()
        response = client.get(reverse("dashboard:api_stream_metrics"))
        self.assertEqual(response.status_code, 200)
        asyncio.run(response.streaming_content.aclose())
