from netinsight.config import settings
from netinsight.config.singletons import get_dse_engine


def global_settings(request):
    """Exposes global settings parameters and DSE actionable alerts to all HTML templates."""
    try:
        dse_alerts = get_dse_engine().evaluate_decisions()
    except Exception:
        dse_alerts = []
    return {
        "demo_mode": settings.DEMO_MODE,
        "dse_alerts": dse_alerts,
        "dse_alerts_count": len(dse_alerts),
    }
