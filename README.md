# NetInsight-X

**NetInsight-X: An Intelligent Decision Support System for Network Monitoring, Traffic Analytics, Optimization, and Predictive Network Management**

[![Live on Render](https://img.shields.io/badge/Render-Live%20Demo-blue?style=for-the-badge&logo=render)](https://netinsight-x.onrender.com/)

> **Live Application URL:** [https://netinsight-x.onrender.com/](https://netinsight-x.onrender.com/)

NetInsight-X is an academic interdisciplinary project integrating Python Programming, Computer Networks, and Mathematics for Computing III. The objective is to build an intelligent network management platform that captures live Local Area Network (LAN) traffic, performs traffic analytics, predicts future network states using Markov Chains, recommends advisory actions via a Markov Decision Process (MDP), optimizes bandwidth allocation using Linear Programming (LP) and CVXOPT, and classifies flows using a Support Vector Machine (SVM), presenting results through a responsive Django dashboard.

---

## 1. System Architecture Layers

```
Presentation Layer (Django + Chart.js)
       ↑
Decision Layer (MDP Advisory Policy)
       ↑
Intelligence Layer (Markov Chain + RBF SVM Classifier)
       ↑
Optimization Layer (LP + CVXOPT + Numerical KKT Verification)
       ↑
Analytics Layer (Pandas Metrics Aggregation)
       ↑
Storage Layer (SQLite)
       ↑
Packet Capture Layer (Multi-threaded Scapy Sniffer / Replay Mode)
```

---

## 2. Prerequisites & Installation

### 2.1 Windows Environment Setup
1. **Python 3.10+** (verified with Python 3.10.12).
2. **Npcap**: Scapy requires Npcap to capture live sockets on Windows.
   * Download and install **[Npcap](https://npcap.com/)**.
   * Select *"Install Npcap in WinPcap API-compatible Mode"* during installation.
3. **Elevated Privileges (Administrator)**: Raw socket packet sniffing requires Administrator permissions on Windows. Run your terminal (cmd/PowerShell) as Administrator.

### 2.2 Linux / macOS Environment Setup
* **Linux:** Install `libpcap-dev` and run with `sudo`, or grant capabilities to Python:
  ```bash
  sudo apt-get install libpcap-dev
  sudo setcap cap_net_raw,cap_net_admin=eip /path/to/venv/bin/python
  ```
* **macOS:** `libpcap` is usually pre-installed; run with `sudo` for live capture.

### 2.3 Quickstart Commands
From the project root folder:

```bash
# 1. Initialize virtual environment
python -m venv venv

# 2. Activate virtual environment
source venv/bin/activate  # Linux/macOS
# .\venv\Scripts\Activate.ps1  # PowerShell
# .\venv\Scripts\activate.bat  # CMD

# 3. Install requirements
pip install -r requirements.txt

# 4. (Optional) Train/regenerate the SVM model files
python -m netinsight.classification.train

# 5. Collect static files for deployment
python manage.py collectstatic --noinput

# 6. Initialize Django Database
python manage.py migrate

# 7. Start Django Application
python manage.py runserver
```

Open your browser and navigate to: **[http://localhost:8000/](http://localhost:8000/)**

---

## 3. Project Configuration

Configuration is managed via environment variables and **`netinsight/config/settings.py`**.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DJANGO_SECRET_KEY` | (development fallback) | Django secret key. **Must be set in production.** |
| `DEBUG` | `True` | Set to `False` in production. |
| `ALLOWED_HOSTS` | `*` | Comma-separated list of hosts. |
| `DATABASE_URL` or `NETINSIGHT_DB_PATH` | `netinsight/database/netinsight.db` | Path to the SQLite database. |
| `NETINSIGHT_SVM_PATH` | `netinsight/classification/svm_model.joblib` | Path to the persisted SVM model. |
| `NETINSIGHT_DEMO_MODE` | `True` | Set to `False` to capture live traffic. |
| `NETINSIGHT_LOG_LEVEL` | `INFO` | Logging level for the `netinsight` logger. |

Core tunables in `netinsight/config/settings.py`:
* **`CAPTURE_INTERFACE`**: Network adapter index to bind to (`None` for auto-detect).
* **`LINK_CAPACITY`**: Bandwidth scale in bps (default: `100_000_000.0` = 100 Mbps).
* **`QOS_PRIORITIES` / `QOS_MIN_BANDWIDTH` / `QOS_MAX_BANDWIDTH`**: Optimization weights and bounds.
* **`STATE_THRESHOLDS`**: Markov state classification thresholds.

For Render and other PaaS deployments, use the env variables above instead of editing `settings.py`.

---

## 4. Run Diagnostic Tests

To run the complete test suite verifying all modules (capture, database, analytics, optimization, prediction, classification, and views):

```bash
python -m unittest discover -s netinsight/tests/
```

To apply linting and style checks:

```bash
ruff check netinsight/ manage.py
```

---

## 5. Folder Structure

```
netinsight/
│
├── config/                  # Django & custom settings
├── capture/                 # Scapy packet parsing & threads sniffer
├── database/                # SQLite schemas and index setups
├── analytics/               # Pandas traffic aggregates calculator
├── optimization/            # LP Bandwidth Optimizer & KKT verifier
├── prediction/              # Markov forecasting & MDP policies
├── classification/          # SVM models and training scripts
├── dashboard/               # Django views, URLs, and Bootstrap HTMLs
├── tests/                   # Module unit and integration tests
└── docs/                    # IEEE Reports, SRS, and formulations
```

---

## 6. Detailed Mathematical Reports
For full mathematical derivations, variables, and algorithms, refer to:
* **Installation & Operations:** [docs/Installation.md](docs/Installation.md)
* **Configuration Reference:** [docs/Configuration.md](docs/Configuration.md)
* **SRS & Technical Report:** [docs/IEEE_Report.md](docs/IEEE_Report.md)
* **Mathematical Derivations:** [docs/Mathematical_Formulation.md](docs/Mathematical_Formulation.md)
* **Database Schema Layout:** [docs/DatabaseDesign.md](docs/DatabaseDesign.md)
* **Programmatic APIs:** [docs/API.md](docs/API.md)
* **System Architecture:** [docs/Architecture.md](docs/Architecture.md)
