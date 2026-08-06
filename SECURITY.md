# Security Posture

This document describes the security mechanisms implemented in NetInsight-X.

## Agent Token Authentication
Agents authenticating with NetInsight-X telemetry endpoints must provide an `X-Agent-Token` header. This token is verified securely using constant-time HMAC validation to prevent timing attacks.

## Production Deployment Rules
When running in production mode (`DEBUG=False`):
- A secure `DJANGO_SECRET_KEY` (32+ characters) is required.
- `NETINSIGHT_AGENT_TOKEN` must be set in the environment variables.
- `ALLOWED_HOSTS` must be strictly defined and not contain `*`.

## Input Validation and HTML Escaping
To prevent Cross-Site Scripting (XSS), all user input rendered in HTML is automatically escaped using Django's template engine. Any dynamic values rendered from variables are sanitized before reaching the browser.
