"""Tests for netinsight/dashboard/process_lock.py — the cross-process singleton lock used to
prevent multi-worker gunicorn deployments from starting N redundant copies of background
threads (speed monitor, DB pruner, demo generator)."""
import os
import unittest
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")
import django

django.setup()

from netinsight.config import settings
from netinsight.dashboard.process_lock import acquire_singleton_lock


class TestProcessLock(unittest.TestCase):

    def _lock_path(self, name: str) -> Path:
        return Path(settings.BASE_DIR) / ".locks" / f"{name}.lock"

    def tearDown(self):
        for name in ("test-lock-a", "test-lock-b"):
            path = self._lock_path(name)
            if path.exists():
                path.unlink()

    def test_first_caller_wins_second_caller_loses(self):
        lock_path = self._lock_path("test-lock-a")
        if lock_path.exists():
            lock_path.unlink()

        first = acquire_singleton_lock("test-lock-a")
        second = acquire_singleton_lock("test-lock-a")

        self.assertTrue(first)
        self.assertFalse(second)

    def test_stale_lock_from_dead_pid_is_reclaimed(self):
        lock_path = self._lock_path("test-lock-b")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        # A PID astronomically unlikely to be a running process on any real machine.
        lock_path.write_text("999999")

        won = acquire_singleton_lock("test-lock-b")
        self.assertTrue(won)


if __name__ == "__main__":
    unittest.main()
