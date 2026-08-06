"""Shared utility functions and authorization validators for NetInsight-X dashboard views."""

import hmac
from typing import Any

import numpy as np
from django.http import JsonResponse

from netinsight.config import settings


def to_native_types(obj: Any) -> Any:
    """Recursively converts numpy/pandas scalars to plain Python types for JSON serialization."""
    if isinstance(obj, dict):
        return {k: to_native_types(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_native_types(v) for v in obj]
    if isinstance(obj, (np.generic,)):
        return obj.item()
    return obj


def check_dashboard_auth(request):
    """Returns HttpResponse 401 if NETINSIGHT_REQUIRE_AUTH is enabled and user is unauthenticated."""
    if getattr(settings, "NETINSIGHT_REQUIRE_AUTH", False) and (not request.user or not request.user.is_authenticated):
        return JsonResponse({"error": "Authentication required to access dashboard endpoints"}, status=401)
    return None


def validate_agent_token(request) -> bool:
    """Validates optional X-Agent-Token header if NETINSIGHT_AGENT_TOKEN is configured.
    Uses hmac.compare_digest for constant-time comparison to prevent timing attacks."""
    token = getattr(settings, "NETINSIGHT_AGENT_TOKEN", None)
    if token:
        auth_header = request.headers.get("X-Agent-Token") or request.META.get("HTTP_X_AGENT_TOKEN")
        if not auth_header or not hmac.compare_digest(str(auth_header), str(token)):
            return False
    return True


def apply_mdp_overrides(recommended_action: str, priorities: list, min_bounds: list, max_bounds: list) -> tuple:
    """Applies MDP-driven priority/bounds adjustments based on recommended action.
    Returns (adjusted_priorities, adjusted_min_bounds, adjusted_max_bounds)."""
    p = list(priorities)
    m = list(min_bounds)
    x = list(max_bounds)
    if recommended_action == "Prioritize Critical Services" and len(p) >= 4:
        p[3] = float(p[3] * 2.0)
        m[3] = float(m[3] * 1.5)
        p[2] = float(p[2] * 0.5)
    elif recommended_action == "Reroute Traffic" and len(p) >= 3:
        p[0] = float(p[0] * 1.5)
        p[1] = float(p[1] * 0.5)
        p[2] = float(p[2] * 0.2)
    return p, m, x
