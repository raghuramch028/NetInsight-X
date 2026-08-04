from django.apps import AppConfig
import os


class DashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "netinsight.dashboard"

    def ready(self):
        import sys
        # Check if executing via local development runserver auto-reloader
        is_manage_py = any(x.endswith('manage.py') for x in sys.argv)
        is_runserver = 'runserver' in sys.argv
        
        if is_manage_py and is_runserver:
            if os.environ.get('RUN_MAIN') == 'true':
                from netinsight.dashboard.speed_monitor import start_speed_monitor
                start_speed_monitor()
        else:
            # Under Gunicorn production web servers, initialize the thread directly
            from netinsight.dashboard.speed_monitor import start_speed_monitor
            start_speed_monitor()
