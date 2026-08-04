from django.apps import AppConfig
import os


class DashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "netinsight.dashboard"

    def ready(self):
        # Prevent starting twice during django autoreload
        if os.environ.get('RUN_MAIN') == 'true' or not os.environ.get('DEBUG'):
            from netinsight.dashboard.speed_monitor import start_speed_monitor
            start_speed_monitor()
