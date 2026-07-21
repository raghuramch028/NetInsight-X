# NetInsight-X

**NetInsight-X: An AI-Driven Distributed Network Monitoring, Traffic Analytics, and Decision Support System (DSS)**

[![Live Demo](https://img.shields.io/badge/Render-Live%20Demo-blue?style=for-the-badge&logo=render&logoColor=white)](https://netinsight-gnt6.onrender.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework: Django](https://img.shields.io/badge/Framework-Django-092E20?style=for-the-badge&logo=django&logoColor=white)](https://www.djangoproject.com/)

NetInsight-X is an intelligent, high-performance distributed network management and security analysis platform. Integrating Python programming, advanced computer networking, and mathematical modeling, NetInsight-X utilizes a hybrid edge-server architecture. Lightweight client agents deployed on monitored edge hosts perform raw packet captures and hardware profiling, streaming telemetry to a central Django decision support server. The server aggregates flows, classifies cyber threats using an RBF SVM model, decodes network states via a Hidden Markov Model (HMM), and optimizes bandwidth via Linear Programming (LP).

---

## 🚀 Key Features

*   **Distributed Edge Sniffer:** Lightweight, modular Python agent deployed on endpoints (Laptops, Raspberry Pis) using Scapy for non-blocking packet capture and `psutil` for host resource monitoring.
*   **Central REST Ingestion:** High-speed REST API endpoints (`/api/v1/agents/`) supporting remote agent registration, secure handshakes, and periodic telemetry streaming.
*   **Neon Cloud PostgreSQL Integration:** Native bindings to Neon Cloud PostgreSQL for production telemetry logging, with automatic local SQLite fallback for isolated development.
*   **Hybrid Anomaly Classifier:** Combines a Support Vector Machine (SVM) with an RBF kernel (trained on the real CICIDS2017 intrusion dataset using balanced class weights for high threat recall) with fast volumetric heuristic overrides.
*   **Markov State Prediction:** Real-time forecasting across 5 operational states (*Normal, Busy, Congested, Under Attack, Recovering*) decoded from multi-metric sequences using the HMM Viterbi algorithm.
*   **Convex QoS Optimization:** Formulates bandwidth allocation as a constrained Linear Program solved via interior-point methods, validating solutions against primal-dual Karush-Kuhn-Tucker (KKT) numerical conditions.
*   **Interactive Topology Mapping:** Generates real-time, dynamic network visualization graphs using NetworkX and Vis.js (PyVis) embedded in the dashboard.
*   **Comprehensive Audit Exporting:** Instant generation of system audit logs in PDF (compiled via ReportLab), flat CSV transactions, and JSON snapshots.

---

## 📐 System Architecture

```
                                  [ Open Internet (WAN Gateway) ]
                                                │
                                                ▼
  [ Client Device 1 ] ──┐            ┌───[ DSS Router ]───┐
  (psutil + Scapy)      │            │   (Central Server) │
                        ├──(HTTPS)───┤                    ├───(PostgreSQL / Neon)
  [ Client Device 2 ] ──┘            │   - Flow Builder   │
  (psutil + Scapy)                   │   - Hybrid SVM     │
                                     │   - HMM Viterbi    │
                                     │   - LP Allocator   │
                                     └────────────────────┘
```

---

## 🛠️ Installation & Setup

### 1. Prerequisites
*   **Python 3.10+** (verified with Python 3.10.12).
*   **Npcap (Windows only):** Required by Scapy for raw packet captures. Download from **[Npcap.com](https://npcap.com/)** and install with *"WinPcap API-compatible Mode"* enabled.
*   **Administrative Privileges:** Required on client devices to open raw sockets for sniffing.

### 2. Quickstart Server Commands
From the project root directory:

```bash
# 1. Initialize virtual environment
python -m venv venv

# 2. Activate virtual environment
# Windows (PowerShell): .\venv\Scripts\Activate.ps1
# Windows (CMD):        .\venv\Scripts\activate.bat
# Linux/macOS:          source venv/bin/activate
source venv/bin/activate

# 3. Install packages
pip install -r requirements.txt

# 4. Train the SVM model binaries
python -m netinsight.classification.train

# 5. Initialize Database schemas
python manage.py migrate

# 6. Collect static assets
python manage.py collectstatic --noinput

# 7. Start Django development server
python manage.py runserver
```

Server local URL: **[http://localhost:8000/](http://localhost:8000/)**

---

## 🛰️ Running the Distributed Client Agent

To connect and monitor edge devices:

1.  Copy the `agent/` folder from this repository onto the client device.
2.  Install dependencies on the client device:
    ```bash
    pip install psutil scapy requests
    ```
3.  Open `agent/config.py` in a text editor and update the target server endpoint:
    ```python
    SERVER_URL = "https://netinsight-gnt6.onrender.com"  # Or http://localhost:8000 for local server
    ```
4.  Run the agent from terminal as administrator:
    ```bash
    python -m agent.main
    ```

---

## ⚙️ Configuration Reference

Managed via local `.env` variables or editing `netinsight/config/settings.py`:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DJANGO_SECRET_KEY` | *(fallback)* | Secret key for Django cryptographic signatures. |
| `DATABASE_URL` | *(SQLite)* | Connection string for remote PostgreSQL (Neon). |
| `DEBUG` | `True` | Set to `False` in production environments. |
| `NETINSIGHT_DEMO_MODE` | `True` | Emulates background traffic if no agents are online. |
| `LINK_CAPACITY` | `100_000_000.0` | Target link speed scale in bps (100 Mbps). |

---

## 📊 Directory Layout

```
NetInsight-X/
│
├── agent/                   # Modular client agent (collector, sniffer, sender)
│
├── netinsight/
│   ├── config/              # Django settings & custom environment variables
│   ├── analytics/           # Flow Builder, Telemetry handler & Topology generator
│   ├── classification/      # SVM RBF model, scaler & training pipeline
│   ├── prediction/          # Viterbi HMM state forecasting & DSE alerting
│   ├── optimization/        # LP bandwidth solver & KKT checker
│   └── dashboard/           # Django templates, styling, views & REST routes
│
├── data/                    # Local storage for CSV training sets
├── requirements.txt         # Package dependencies file
└── build.sh                 # Automatic build script for Render deployment
```

---

## 📜 Academic Formulations & Reports
For deep-dives into mathematics, specifications, and architecture:
*   **Operational Manual:** [docs/Installation.md](docs/Configuration.md)
*   **Technical Draft Report:** [docs/IEEE_Report.md](docs/IEEE_Report.md)
*   **Mathematical Derivations:** [docs/Mathematical_Formulation.md](docs/Mathematical_Formulation.md)
*   **Database Design Schemas:** [docs/DatabaseDesign.md](docs/DatabaseDesign.md)
