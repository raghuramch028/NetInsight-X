# Developer Guide - NetInsight-X

This guide is for contributors and maintainers who want to understand, build, and extend NetInsight-X.

---

## 1. Development Environment

The project is a standard Python 3.10 Django application. It has been tested on Ubuntu with Python 3.10.12 and in a Windows environment with Npcap.

```bash
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Optional: Local SVM retraining

The repository ships pre-generated `svm_model.joblib` / `scaler.joblib`. To regenerate them (e.g., after a scikit-learn upgrade):

```bash
python -m netinsight.classification.train
```

If `data/UNSW_NB15_training-set.csv` and `data/UNSW_NB15_testing-set.csv` are not present, the script uses a deterministic synthetic dataset.

---

## 2. Running the Application Locally

```bash
python manage.py migrate
python manage.py runserver
```

The dashboard starts in `DEMO_MODE` by default, which simulates traffic so the UI is immediately usable without raw socket privileges.

To test live capture on Linux/macOS, install `libpcap-dev` and run with `sudo`, or grant Python the `cap_net_raw` capability:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(realpath venv/bin/python)
NETINSIGHT_DEMO_MODE=False python manage.py runserver
```

---

## 3. Running Tests and Lint

### Full test suite

```bash
python -m unittest discover -s netinsight/tests/
```

All tests use temporary directories and restore `settings.DB_PATH` / `settings.SVM_MODEL_PATH` afterwards so they do not overwrite committed artifacts.

### Lint

```bash
ruff check netinsight/ manage.py
```

`pyproject.toml` configures `ruff` for Python 3.10, a 120-character line length, and relaxed import-order rules for Django test modules that call `django.setup()` before app imports.

---

## 4. Project Layout

```
netinsight/
├── config/          # Django settings and shared constants
├── capture/         # Scapy packet parser and LiveMonitor threads
├── database/        # SQLite schema and access helpers
├── analytics/       # Pandas aggregation engine
├── optimization/    # CVXOPT LP solver and numerical KKT verifier
├── prediction/      # Markov state forecasting and MDP policy engine
├── classification/  # RBF SVM training and inference
├── dashboard/       # Django views, URLs, and Bootstrap/Chart.js templates
└── tests/           # Module unit and integration tests
```

---

## 5. Key Design Decisions

* **Single SQLite database:** All layers share `settings.DB_PATH`. Raw SQL is used in the capture worker for low overhead; Pandas `read_sql_query` is used in analytics. This keeps the project self-contained and deployable without an external database.
* **Bounded producer-consumer queue:** `LiveMonitor` uses `queue.Queue(maxsize=MAX_QUEUE_SIZE)` and a writer thread to decouple packet arrival from SQLite inserts. Under pressure, packets are dropped rather than consuming unbounded memory.
* **Lazy monitor start:** `views.ensure_monitor_started()` instantiates the global `LiveMonitor` on the first dashboard request. This avoids running background threads during Django management commands such as `migrate` or `collectstatic`.
* **Settings read at call time:** `db_manager.get_connection()` and `classification/train.py` resolve `DB_PATH` and `SVM_MODEL_PATH` when functions are called, not at import time. This allows tests to patch paths without leaking state across modules.
* **Fallback everywhere:**
  * Missing SVM model → deterministic heuristic classifier.
  * Infeasible LP → proportional fallback allocation.
  * Empty database → default/zero metrics and empty charts.

---

## 6. Adding a New Dashboard Page

1. Add a view to `netinsight/dashboard/views.py` and wire it in `netinsight/dashboard/urls.py`.
2. Create a template that extends `dashboard/base.html`.
3. Keep the sidebar `active` class consistent with the page identifier.
4. Use the CSS variables defined in `base.html` (`--bg-secondary`, `--accent-blue`, etc.) for consistent styling.
5. Add a unit/integration test in `netinsight/tests/test_dashboard.py` that patches `settings.DB_PATH` to a temporary database.

---

## 7. Common Issues

| Symptom | Likely Cause | Fix |
| :--- | :--- | :--- |
| `DJANGO_SECRET_KEY is not set` warning | Running with the development fallback key | Set `DJANGO_SECRET_KEY` in production |
| `InconsistentVersionWarning` from sklearn | `svm_model.joblib` was saved with a different scikit-learn version | Run `python -m netinsight.classification.train` |
| `raw socket` / permission errors | Missing `cap_net_raw` or not running as root/Administrator | Use `sudo`, grant capabilities, or enable `DEMO_MODE` |
| Port 8000 already in use | Another Django process running | `kill` the old process or use `python manage.py runserver 0.0.0.0:8001` |
| Missing icons in UI | Invalid `data-lucide` icon name | Use names from the `lucide@0.263.0` icon set |
