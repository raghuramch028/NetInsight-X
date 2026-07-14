from netinsight.config import settings


def global_settings(request):
    """Exposes global settings parameters to all HTML templates."""
    return {
        "demo_mode": settings.DEMO_MODE
    }
