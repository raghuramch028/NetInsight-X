# Configuration Guide - NetInsight-X

NetInsight-X separates runtime configuration into environment variables (recommended for production and PaaS deployments) and editable constants in `netinsight/config/settings.py`.

---

## 1. Environment Variables

These variables are read at runtime from the process environment. Render, Heroku, and other hosts should set them in the platform dashboard rather than editing files.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DJANGO_SECRET_KEY` | `django-insecure-netinsightx-academic-project-secret` | Django signing/CSRF secret. **Set a strong, random value in production.** |
| `DEBUG` | `True` | Set to `False` in production to disable verbose error pages and reduce attack surface. |
| `ALLOWED_HOSTS` | `*` | Comma-separated list of hostnames the server will accept. Set to your domain(s) in production. |
| `DATABASE_URL` or `NETINSIGHT_DB_PATH` | `netinsight/database/netinsight.db` | Path to the SQLite database file. `DATABASE_URL` supports `sqlite:///` prefixes. |
| `NETINSIGHT_SVM_PATH` | `netinsight/classification/svm_model.joblib` | Path to the persisted SVM model. A sibling `scaler.joblib` is expected in the same directory. |
| `NETINSIGHT_DEMO_MODE` | `True` | When `True`, simulated traffic is generated. Set `False` for live interface sniffing. |
| `NETINSIGHT_LOG_LEVEL` | `INFO` | Logging level for the `netinsight` logger (e.g., `DEBUG`, `INFO`, `WARNING`, `ERROR`). |

### 1.1 Example `.env`

```bash
DJANGO_SECRET_KEY=your-production-secret-key-here
DEBUG=False
ALLOWED_HOSTS=netinsight-x.onrender.com,localhost
NETINSIGHT_DB_PATH=/opt/netinsight/data/netinsight.db
NETINSIGHT_SVM_PATH=/opt/netinsight/models/svm_model.joblib
NETINSIGHT_DEMO_MODE=False
NETINSIGHT_LOG_LEVEL=INFO
```

---

## 2. Core `settings.py` Tunables

Open `netinsight/config/settings.py` to adjust algorithm parameters. Values below are the shipped defaults.

### 2.1 Capture Settings

* `CAPTURE_INTERFACE = None`
  * Network adapter index passed to Scapy. `None` lets Scapy auto-detect. On multi-interface systems, set an integer index.
* `DEMO_MODE = True`
  * When `True`, the capture thread generates synthetic packets that transition through NORMAL, BUSY, CONGESTED, and FAILURE states. Requires no raw socket privileges.

### 2.2 Network Link Settings

* `LINK_CAPACITY = 100_000_000.0`
  * Total link capacity in bits per second (100 Mbps). Used to compute utilization percentages and LP total capacity.
* `QOS_PRIORITIES = [1.0, 2.0, 0.5, 3.0]`
  * Utility weights for Web Browsing, Streaming, File Transfer, and Critical Services.
* `QOS_MIN_BANDWIDTH = [5e6, 15e6, 2e6, 10e6]`
  * Minimum guaranteed bandwidth in bps for each class.
* `QOS_MAX_BANDWIDTH = [40e6, 60e6, 30e6, 50e6]`
  * Maximum allowed bandwidth in bps for each class.

### 2.3 State Classification Thresholds

`STATE_THRESHOLDS` controls how the predictor and monitor map utilization and packet loss to states:

```python
STATE_THRESHOLDS = {
    "BUSY":       {"util_min": 0.40, "util_max": 0.75, "loss_max": 0.05},
    "CONGESTED":  {"util_min": 0.75, "util_max": 0.95, "loss_max": 0.10},
    "FAILURE":    {"util_min": 0.95, "loss_max": 0.10},
}
```

* `NORMAL` is the implicit default when none of the above conditions are met.
* `FAILURE` triggers when utilization is at least `util_min` **or** loss is at least `loss_min`.

### 2.4 Capture Tuning

* `PACKET_BATCH_SIZE = 50`
  * Number of parsed packets inserted into SQLite in a single transaction.
* `METRICS_WINDOW_SECONDS = 2.0`
  * How frequently the writer thread recomputes and stores metrics.
* `MAX_QUEUE_SIZE = 1000`
  * Bounded queue size between capture and writer threads; protects memory under burst traffic.

---

## 3. SVM Model Artifacts

The classifier expects two `joblib` files:

* `<NETINSIGHT_SVM_PATH>` — the trained `SVC` model.
* `<directory of NETINSIGHT_SVM_PATH>/scaler.joblib` — the fitted `StandardScaler`.

If the files are missing, `TrafficClassifier` falls back to a deterministic rule-based classifier using packet size and port heuristics, and the dashboard shows an `OFFLINE` badge.

To regenerate artifacts:

```bash
python -m netinsight.classification.train
```

If official UNSW-NB15 CSV files are not found in `data/`, a deterministic synthetic dataset is generated and used.

---

## 4. Deployment Notes

* `DEBUG=False` requires `python manage.py collectstatic --noinput` so WhiteNoise can serve static files.
* The production entry point used by Render is `netinsight.config.wsgi:application` with Gunicorn.
* `build.sh` runs `collectstatic` and `migrate` automatically on Render.
