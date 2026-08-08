"""Cross-process advisory lock ensuring singleton background threads under multi-worker
deployments (e.g. `gunicorn -w 4`).

Each gunicorn worker is a separate OS process. Background threads started from
AppConfig.ready() or a view (speed monitor, demo-telemetry generator, DB pruner) were
previously started independently by every worker process, multiplying external speed-test
calls, synthetic demo data, and prune-DELETE load by the worker count. This module lets only
one process win a named lock and run the task; the others skip it.
"""
import logging
import os
from pathlib import Path

logger = logging.getLogger("netinsight.process_lock")


def _pid_is_running(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        pass

    try:
        os.kill(pid, 0)
        return True
    except (OSError, AttributeError):
        return False


def acquire_singleton_lock(name: str) -> bool:
    """Attempts to become the single process responsible for a named background task.

    Returns True if this process won the lock (it should start the thread), False if another
    live process already owns it. A lock file whose owning PID is no longer running is treated
    as stale and reclaimed automatically, so a crashed worker doesn't permanently block the task.
    """
    from netinsight.config import settings

    lock_dir = Path(getattr(settings, "BASE_DIR", Path.cwd())) / ".locks"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        # Can't create the lock directory (e.g. read-only filesystem) — fail open so at least
        # one process still performs the task rather than none.
        logger.warning(f"Could not create lock directory ({e}); allowing task '{name}' to start unguarded.")
        return True

    lock_path = lock_dir / f"{name}.lock"
    pid = os.getpid()

    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(pid).encode("utf-8"))
        os.close(fd)
        return True
    except FileExistsError:
        pass

    try:
        existing_pid = int(lock_path.read_text().strip())
    except Exception:
        existing_pid = None

    if existing_pid and _pid_is_running(existing_pid):
        return False

    try:
        lock_path.write_text(str(pid))
        logger.info(f"Reclaimed stale singleton lock '{name}' from dead PID {existing_pid}.")
        return True
    except Exception as e:
        logger.warning(f"Failed to reclaim stale lock '{name}': {e}")
        return False
