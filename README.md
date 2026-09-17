# NetInsight-X

**NetInsight-X: Autonomous Dynamic Bandwidth Allocation, Convex QoS Optimization & Real-Time AI Threat Classification System**

[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework: Django](https://img.shields.io/badge/Framework-Django-092E20?style=for-the-badge&logo=django&logoColor=white)](https://www.djangoproject.com/)
[![Optimization: CVXOPT](https://img.shields.io/badge/Optimization-CVXOPT_LP_%2B_KKT-orange?style=for-the-badge)](https://cvxopt.org/)
[![AI Engine: XGBoost](https://img.shields.io/badge/AI_Engine-XGBoost_CICIoT2023-brightgreen?style=for-the-badge&logo=xgboost)](https://xgboost.readthedocs.io/)

NetInsight-X is an autonomous, high-performance distributed network management, real-time Quality of Service (QoS) Bandwidth Optimization, and AI-powered Anomaly Detection System. Designed for dynamic bandwidth allocation and threat classification across multi-agent endpoints, NetInsight-X combines edge packet telemetry, real-time speed monitoring, convex bandwidth optimization (**CVXOPT Linear Programming + KKT Optimality Verification**), and a custom **XGBoost ML Threat Classifier** trained on the real **CICIoT2023** benchmark dataset.

---

## 🚀 Key Features

* **🛰️ Edge Endpoint Sniffer & Dynamic Agent Telemetry:**
  - **Python Agent (`agent/main.py`)**: Uses Scapy and `psutil` for non-blocking packet header capture, host telemetry streaming, and automated Windows QoS rate-limiting enforcement.
  - **Seamless Wi-Fi / Hotspot Connection**: Agents dynamically discover and connect to the central Django server across any local network or mobile hotspot interface.

* **📐 Convex QoS Bandwidth Optimizer (CVXOPT + KKT):**
  - Solves constrained Linear Programming (LP) bandwidth allocation under dynamic capacity limits.
  - Verifies numerical optimality against Karush-Kuhn-Tucker (KKT) primal-dual stationarity conditions ($10^{-5}$ tolerance) with proportional fallback scaling under link saturation.
  - **Decision Support Engine (DSE)**: Automatically generates real-time QoS control recommendations and policies.

* **⚡ Real-Time Closed-Loop Bandwidth Control:**
  - Dynamic link capacity detection via Google M-Lab NDT7 multi-stream engine.
  - Closed-loop rate limiting and QoS policy feedback dispatched to active edge endpoints.

* **🛡️ AI Threat Intelligence & Anomaly Detection (XGBoost ML Engine):**
  - Custom local **XGBoost Classifier Engine** trained directly on official **CICIoT2023** records (50,000 preprocessed samples per split across 34 raw attack sub-types).
  - Preprocessed dataset mapping into 5 target threat classes: **Normal (0)**, **DoS / DDoS (1)**, **Mirai Botnet (2)**, **Reconnaissance (3)**, and **Brute Force (4)**.
  - High generalization accuracy: **99.43% Train Accuracy**, **98.87% Validation Accuracy**, and **98.70% Test Accuracy**.
  - **Sub-millisecond Inference**: Inference latency **< 0.5 ms** loaded via precompiled weight matrix (`xgboost_threat_model.joblib`).

* **🔒 Security & Production Posture:**
  - Full HTML input escaping and MAC/IP address validation on agent registration against Stored XSS and malformed input.
  - Constant-time shared-secret agent token authentication (`X-Agent-Token`, validated via `hmac.compare_digest`).
  - Optional dashboard-user authentication gate (`NETINSIGHT_REQUIRE_AUTH`).

* **📊 Interactive Live Dashboard:**
  - Modern web dashboard featuring real-time Chart.js throughput streams, active device topology graph, AI Threat Intelligence auditor, Lucide icons, and live telemetry streaming.

---

## 📐 System Architecture

```
                       [ Open Internet / Edge Host Endpoints ]
                                         │
                                         ▼
  [ Python Edge Agent ] ─────────► [ Central Server ]
  (agent/main.py)                  (Django 5.2 Server)
  - Raw Packet Capture             - REST Telemetry Ingestion
  - Host Telemetry Streaming       - CVXOPT LP Bandwidth Solver
  - Windows NDIS QoS Enforcement   - KKT Optimality Verification
                                   - XGBoost Threat Classifier (CICIoT2023)
                                   - Google NDT7 Capacity Monitor
```

---

## 🛠️ Quickstart Installation & Setup

### 1. Prerequisites
* **Python 3.10+** (verified with Python 3.10 / 3.14).
* **Npcap (Windows only):** Required by Scapy on Windows for raw packet captures. Download from **[Npcap.com](https://npcap.com/)** (*WinPcap API-compatible Mode* enabled).

### 2. Start the NetInsight-X Server

Open **PowerShell** or Terminal in the project root folder:

```powershell
# 1. Activate Virtual Environment
.\venv\Scripts\Activate.ps1

# 2. Run Database Migrations
python manage.py migrate

# 3. Start Development Server (accessible locally & over Wi-Fi)
python manage.py runserver 0.0.0.0:8000
```

Access the Web Dashboard at:
- **Local Laptop**: [http://localhost:8000](http://localhost:8000)
- **Local Network**: `http://<YOUR-LOCAL-IP>:8000`

---

## 🛰️ Running the Edge Endpoint Agent

To connect and monitor edge client devices:

On the monitored client device:
```powershell
python -m agent.main --server http://<SERVER-IP>:8000
```

---

## 🧪 System Verification & Code Quality

NetInsight-X maintains strict code quality and verification:

```powershell
# Run Linter (0 errors)
ruff check .

# Run Django System Check (0 issues)
python manage.py check

# Train/Evaluate XGBoost Threat Model
python scratch/train_xgboost_threat_model.py
```

---

## 🚢 Production Deployment Notes

* **Live-stream endpoint (`/api/v1/stream/metrics/`)** is a native async Django view (Server-Sent
  Events). **Run it under an ASGI server** to get the real benefit:
  ```powershell
  # ASGI (recommended) — uvicorn worker under gunicorn, or run uvicorn directly
  gunicorn netinsight.asgi:application -k uvicorn.workers.UvicornWorker -w 4
  # or, for local/simple deployments:
  uvicorn netinsight.asgi:application --host 0.0.0.0 --port 8000
  ```
* **Multi-worker deployments** (`gunicorn -w N`): the speed monitor, DB pruner, and demo-data
  generator background threads use a cross-process file lock (`netinsight/.locks/`) so only one
  worker process runs each task, regardless of `N`.
* **Health check**: `GET /healthz` returns `{"status": "ok", "database": true}` with no
  authentication required, for load balancers / orchestration platforms.

---

## 📄 License & Attribution

Distributed under the **MIT License**. Built with Django, CVXOPT, XGBoost, Scikit-Learn, NumPy, Pandas, Chart.js, and Lucide.

---

## 📊 Directory Layout

```
NetInsight-X/
│
├── manage.py                # Django CLI entrypoint
├── pyproject.toml           # Project metadata and configuration
├── requirements.txt         # Package dependencies file
│
├── agent/                   # Modular Python client agent (collector, sniffer, sender, QoS)
│
├── scratch/                 # Offline ML model training scripts & artifacts
│
└── netinsight/
    ├── config/              # Central settings & singleton registries
    ├── analytics/           # Flow builder, Telemetry handler & Topology generator
    ├── classification/      # XGBoost ML Threat Classifier Engine & Model weights (.joblib)
    ├── optimization/        # CVXOPT Convex LP bandwidth solver & KKT verifier
    └── dashboard/           # Django templates, styling, views package & REST routes
```

