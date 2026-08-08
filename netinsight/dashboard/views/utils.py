"""Shared utility functions and authorization validators for NetInsight-X dashboard views."""

import asyncio
import hmac
from functools import wraps
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


def require_dashboard_auth(view_func):
    """Decorator enforcing check_dashboard_auth() on a dashboard page or read-only API view."""
    if asyncio.iscoroutinefunction(view_func):
        @wraps(view_func)
        async def async_wrapper(request, *args, **kwargs):
            auth_response = check_dashboard_auth(request)
            if auth_response is not None:
                return auth_response
            return await view_func(request, *args, **kwargs)

        return async_wrapper

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_response = check_dashboard_auth(request)
        if auth_response is not None:
            return auth_response
        return view_func(request, *args, **kwargs)

    return wrapper


def validate_agent_token(request) -> bool:
    """Validates X-Agent-Token header if NETINSIGHT_AGENT_TOKEN is configured."""
    token = getattr(settings, "NETINSIGHT_AGENT_TOKEN", None)
    enforce = getattr(settings, "NETINSIGHT_ENFORCE_AGENT_TOKEN", False)
    if token or enforce:
        auth_header = request.headers.get("X-Agent-Token") or request.META.get("HTTP_X_AGENT_TOKEN")
        if not auth_header or not token or not hmac.compare_digest(str(auth_header), str(token)):
            return False
    return True
