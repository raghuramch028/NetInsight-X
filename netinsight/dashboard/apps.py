import os

from django.apps import AppConfig


class DashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "netinsight.dashboard"

    def ready(self):
        import sys
        # Check if executing via local development runserver auto-reloader
        is_manage_py = any(x.endswith('manage.py') for x in sys.argv)
        is_runserver = 'runserver' in sys.argv
        is_test = 'test' in sys.argv

        if is_test:
            # Don't start any background threads during the test suite — they touch the DB on
            # their own timers and would race against per-test database resets.
            return

        if is_manage_py and is_runserver:
            if os.environ.get('RUN_MAIN') == 'true':
                self._start_background_tasks()
        else:
            # Under Gunicorn / other production servers, initialize directly. Each worker process
            # calls this; start_speed_monitor() and start_periodic_pruner() each use a
            # cross-process singleton lock (see process_lock.py) so only one worker actually
            # runs each task instead of every worker running N redundant copies.
            self._start_background_tasks()

    @staticmethod
    def _start_background_tasks():
        from netinsight.analytics.telemetry_handler import start_periodic_pruner
        from netinsight.dashboard.speed_monitor import start_speed_monitor

        start_speed_monitor()
        start_periodic_pruner()
