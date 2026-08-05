# NetInsight-X Deployment Guide

This guide covers deployment instructions for NetInsight-X using Docker, environment configuration options, security checklists, and required permissions for QoS shaping.

## Docker Deployment

You can quickly deploy NetInsight-X using Docker and docker-compose. 

1. **Build and start the container:**
   ```bash
   docker-compose up -d --build
   ```

2. **Access the application:**
   Navigate to `http://localhost:8000` in your web browser.

3. **Stop the container:**
   ```bash
   docker-compose down
   ```

## Environment Configuration

You can customize the deployment by setting the following environment variables in your `docker-compose.yml`:

| Variable | Description | Default |
|---|---|---|
| `DEBUG` | Enable Django debug mode (set to False for production) | `False` |
| `NETINSIGHT_DEMO_MODE` | Enable demo mode for simulation | `True` |
| `NETINSIGHT_LINK_CAPACITY` | Base link capacity in bits per second | `100000000.0` (100 Mbps) |
| `NETINSIGHT_REFRESH_INTERVAL` | Dashboard auto-refresh interval in milliseconds | `2000` |

## Security Checklist

Before deploying to a production environment, ensure you review the following:

- [ ] Ensure `DEBUG=False` in environment variables.
- [ ] Change the default Django `SECRET_KEY` and do not expose it.
- [ ] Configure `ALLOWED_HOSTS` to include only the domains/IPs you expect.
- [ ] Ensure the container runs as a non-root user (if hardware QoS is not needed, see below).
- [ ] Place the deployment behind a reverse proxy (like Nginx) configured with TLS/SSL.
- [ ] Mount persistent volumes securely for the SQLite database or migrate to PostgreSQL.

## Elevated OS Permissions for Hardware QoS Shaping

NetInsight-X includes features for hardware-level QoS (Quality of Service) shaping. If you intend to use real hardware shaping rather than simulation (`NETINSIGHT_DEMO_MODE=False`), the application will require elevated privileges.

### Linux (Traffic Control / `tc`)
To manipulate network interfaces using `tc`, the container requires the `NET_ADMIN` capability.
Update your `docker-compose.yml` to include:

```yaml
services:
  web:
    # ...
    cap_add:
      - NET_ADMIN
    # Optional: run in host network mode to shape physical interfaces
    # network_mode: "host"
```
You may also need to run the application process as `root` within the container or configure specific `sudo` permissions for the user executing shaping scripts.

### Windows (QoS Policies)
Hardware shaping on Windows requires running the service with Administrator privileges to interact with Windows QoS APIs or PowerShell cmdlets for Network QoS policies. Standard containerized deployment on Windows may have limited access to host network adapters for shaping.

> **Warning:** Granting elevated privileges or `NET_ADMIN` capabilities increases the security risk. Only enable these features if explicitly required and isolate the environment accordingly.
