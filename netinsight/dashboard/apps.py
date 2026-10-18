import os

from django.apps import AppConfig


class DashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "netinsight.dashboard"

    def ready(self):
        import sys
        is_manage_py = any(x.endswith('manage.py') for x in sys.argv)
        is_runserver = 'runserver' in sys.argv

        if is_manage_py:
            if is_runserver and (os.environ.get('RUN_MAIN') == 'true' or '--noreload' in sys.argv):
                self._start_background_tasks()
            return

        # ASGI/WSGI servers initialize directly; process locks prevent duplicate workers.
        self._start_background_tasks()

    @staticmethod
    def _start_background_tasks():
        from netinsight.analytics.telemetry_handler import start_periodic_pruner
        from netinsight.dashboard.speed_monitor import start_speed_monitor

        start_speed_monitor()
        start_periodic_pruner()
