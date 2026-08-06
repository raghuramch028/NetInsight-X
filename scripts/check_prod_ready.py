#!/usr/bin/env python3
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")

def main():
    print("Checking NetInsight-X Production Readiness...\n")
    issues = []

    try:
        from django.conf import settings
        # Trigger setting load
        _ = settings.DEBUG
    except Exception as e:
        print(f"[FAIL] Error loading settings: {e}")
        print("\nSummary:")
        print("The following issues must be resolved before production deployment:")
        print(f" - {e}")
        sys.exit(1)

    # Check DEBUG
    debug = settings.DEBUG
    print(f"DEBUG Mode: {'[FAIL]' if debug else '[PASS]'} (Value: {debug})")
    if debug:
        issues.append("DEBUG is set to True. Must be False for production.")

    # Check SECRET_KEY
    secret_key = settings.SECRET_KEY
    is_default_secret = secret_key == "django-insecure-netinsightx-academic-project-secret"
    is_short_secret = len(secret_key) < 32
    print(f"SECRET_KEY: {'[FAIL]' if is_default_secret or is_short_secret else '[PASS]'}")
    if is_default_secret:
        issues.append("SECRET_KEY is using the default fallback.")
    if is_short_secret:
        issues.append("SECRET_KEY is too short (must be >= 32 characters).")

    # Check Agent Token
    agent_token = getattr(settings, 'NETINSIGHT_AGENT_TOKEN', None)
    print(f"NETINSIGHT_AGENT_TOKEN: {'[FAIL]' if not agent_token else '[PASS]'}")
    if not agent_token:
        issues.append("NETINSIGHT_AGENT_TOKEN is not set.")

    # Check ALLOWED_HOSTS
    allowed_hosts = settings.ALLOWED_HOSTS
    print(f"ALLOWED_HOSTS: {'[FAIL]' if '*' in allowed_hosts else '[PASS]'} (Value: {allowed_hosts})")
    if '*' in allowed_hosts:
        issues.append("ALLOWED_HOSTS contains '*'.")

    print("\nSummary:")
    if issues:
        print("The following issues must be resolved before production deployment:")
        for issue in issues:
            print(f" - {issue}")
        sys.exit(1)
    else:
        print("All production readiness checks passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()
