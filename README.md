# NetInsight-X

**NetInsight-X: Autonomous Dynamic Bandwidth Allocation and Convex QoS Optimization System**

[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework: Django](https://img.shields.io/badge/Framework-Django-092E20?style=for-the-badge&logo=django&logoColor=white)](https://www.djangoproject.com/)
[![Optimization: CVXOPT](https://img.shields.io/badge/Optimization-CVXOPT_LP_%2B_KKT-orange?style=for-the-badge)](https://cvxopt.org/)

NetInsight-X is an autonomous, high-performance distributed network management and real-time Quality of Service (QoS) Bandwidth Optimization System. Designed for dynamic bandwidth allocation across multi-agent endpoints, NetInsight-X combines edge packet telemetry, real-time speed monitoring, and convex bandwidth optimization (**CVXOPT Linear Programming + Karush-Kuhn-Tucker (KKT) Optimality Verification**).

---

## 🚀 Key Features

* **🛰️ Distributed Multi-Agent Sniffers:**
  - **Python Agent (`agent/main.py`)**: Uses Scapy and `psutil` for non-blocking packet header capture and host telemetry streaming.
  - **Go Agent (`agent_go/main.go`)**: High-throughput Go packet sniffer with support for environment-driven hotspot SSID configuration (`HOTSPOT_SSID`).

* **📐 Convex QoS Bandwidth Optimizer (CVXOPT + KKT):**
  - Solves constrained Linear Programming (LP) bandwidth allocation under dynamic capacity limits (e.g. mobile hotspots at 8.5 Mbps or dynamic speed test capacity).
  - Verifies numerical optimality against Karush-Kuhn-Tucker (KKT) primal-dual stationarity conditions ($10^{-5}$ tolerance) with proportional fallback scaling under link saturation.

* **⚡ Real-Time Closed-Loop Bandwidth Control:**
  - Dynamic link capacity detection via Google M-Lab NDT7 multi-stream engine.
  - Closed-loop rate limiting and QoS policy feedback dispatched to active edge endpoints.

* **🔒 Security & Production Posture:**
  - Full HTML input escaping and MAC/IP address validation on agent registration against Stored XSS and malformed input.
  - Constant-time shared-secret agent token authentication (`X-Agent-Token`, validated via `hmac.compare_digest`).
  - Optional dashboard-user authentication gate (`NETINSIGHT_REQUIRE_AUTH`).

* **📊 Interactive Live Dashboard:**
  - Modern web dashboard featuring real-time Chart.js throughput graphs, active device topology graph, Lucide icons, and live telemetry streaming.

---

## 📐 System Architecture

```
                       [ Open Internet / Edge Host Endpoints ]
                                         │
                                         ▼
  [ Python Edge Agent ] ──┐     ┌───[ Central Server ]───┐
  (agent/main.py)         │     │  (Django 5.2 Server)   │
                          ├────►│                        │
  [ Go Edge Agent ] ─────┤     │  - REST Ingestion      │
  (agent_go/main.go)      │     │  - CVXOPT LP Allocator │
                                │  - KKT Verification    │
                                └────────────────────────┘
```

---

## 🛠️ Quickstart Installation & Setup

### 1. Prerequisites
* **Python 3.10+** (verified with Python 3.10 / 3.14).
* **Npcap (Windows only):** Required by Scapy on Windows for raw packet captures. Download from **[Npcap.com](https://npcap.com/)** (*WinPcap API-compatible Mode* enabled).
* **Go agent build only:** `agent_go/` uses `gopacket/pcap`, which requires libpcap development headers (Linux: `libpcap-dev`) or the Npcap SDK (Windows) at *compile* time — separate from the Npcap runtime above. `go build ./...` / `go vet ./...` have been verified clean against Go 1.26 (`agent_go/go.sum` is checked in and reproducible).

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

## 🛰️ Running Edge Endpoint Agents

To connect and monitor edge devices:

### Option A: Python Agent
On the monitored client device:
```powershell
cd agent
python main.py --server http://<SERVER-IP>:8000
```

### Option B: Go Agent
On the monitored client device:
```powershell
cd agent_go
go run main.go -server http://<SERVER-IP>:8000
```

---

## 🧪 Testing & Code Quality

NetInsight-X features a comprehensive, 100% passing automated test suite covering all REST endpoints, mathematical solvers, threat classification engines, view routes, agent HTTP clients, and background-task singleton locking:

```powershell
# Run Linter (0 errors)
ruff check .

# Run Full Test Suite (68/68 tests passing)
python manage.py test netinsight.tests --keepdb
```

---

## 🚢 Production Deployment Notes

* **Live-stream endpoint (`/api/v1/stream/metrics/`)** is a native async Django view (Server-Sent
  Events). **Run it under an ASGI server** to get the real benefit — each connection then parks
  on a non-blocking `await asyncio.sleep(1.0)` between updates instead of pinning an OS
  thread/worker for its entire lifetime:
  ```powershell
  # ASGI (recommended) — uvicorn worker under gunicorn, or run uvicorn directly
  gunicorn netinsight.asgi:application -k uvicorn.workers.UvicornWorker -w 4
  # or, for local/simple deployments:
  uvicorn netinsight.asgi:application --host 0.0.0.0 --port 8000
  ```
  If you instead run it under plain WSGI gunicorn (`gunicorn netinsight.wsgi:application`),
  Django transparently adapts the async view via `async_to_sync` — it still works correctly, but
  each connection goes back to blocking a worker for its lifetime, same as before this fix.
  Either way, concurrency is additionally bounded (`NETINSIGHT_MAX_SSE_CONNECTIONS`, default 4;
  `NETINSIGHT_SSE_MAX_DURATION`, default 300s) as defense-in-depth, returning `503` instead of
  hanging once the cap is hit.
* **Multi-worker deployments** (`gunicorn -w N`): the speed monitor, DB pruner, and demo-data
  generator background threads use a cross-process file lock (`netinsight/.locks/`) so only one
  worker process runs each task, regardless of `N`.
* **Agent token enforcement**: if you set `NETINSIGHT_AGENT_TOKEN` on the server, set the same
  value in each agent's own environment (`NETINSIGHT_AGENT_TOKEN`) — both agents now send it as
  `X-Agent-Token` automatically. Without it, `NETINSIGHT_ENFORCE_AGENT_TOKEN=True` will reject
  every agent request.
* **Health check**: `GET /healthz` returns `{"status": "ok", "database": true}` with no
  authentication required, for load balancers / orchestration platforms.

---

## 📄 License & Attribution

Distributed under the **MIT License**. Built with Django, NVIDIA NIM API, CVXOPT, Scipy, NumPy, Pandas, Chart.js, and Lucide.

---

## ⚙️ Configuration Reference

Managed via local `.env` variables (see [`.env.example`](.env.example) for the full annotated
list) or editing `netinsight/config/settings.py`:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DJANGO_SECRET_KEY` | *(fallback)* | Secret key for Django cryptographic signatures. |
| `DEBUG` | `True` | Set to `False` in production environments. |
| `NETINSIGHT_AGENT_TOKEN` | *(optional)* | Shared secret HTTP header token for agent authentication (server + both agents). |
| `NETINSIGHT_ENFORCE_AGENT_TOKEN` | `False` | Reject agent requests missing/mismatching the token, even in DEBUG mode. |
| `NETINSIGHT_REQUIRE_AUTH` | `False` | Require an authenticated Django user for the dashboard and read-only APIs. |
| `NETINSIGHT_FORCE_HTTPS` | `False` | Enables HSTS + secure cookies; only set this behind TLS termination. |
| `NETINSIGHT_MAX_SSE_CONNECTIONS` | `4` | Concurrent live-stream connections before returning `503`. |
| `NETINSIGHT_MAX_INFLIGHT_TELEMETRY_TASKS` | `16` | Concurrent background telemetry-processing tasks before a tick is skipped. |
| `NETINSIGHT_PRUNE_INTERVAL_SECONDS` | `60` | How often stale records are purged from the database. |

---

## 📊 Directory Layout

```
NetInsight-X/
│
├── agent/                   # Modular Python client agent (collector, sniffer, sender, QoS)
├── agent_go/                # High-speed Go client agent
│
├── netinsight/
│   ├── config/              # Central settings & singleton registries
│   ├── analytics/           # Flow builder, Telemetry handler & Topology generator
│   ├── optimization/        # CVXOPT Convex LP bandwidth solver & KKT verifier
│   ├── dashboard/           # Django templates, styling, views package & REST routes
│   └── tests/               # Regression and integration test suites
│
└── requirements.txt         # Package dependencies file
```

---

## 📜 Academic Formulations & Reports
For deep-dives into mathematics, specifications, and architecture:
* **Academic Paper**: [`docs/IEEE_Report.md`](file:///C:/Users/raghu/.gemini/antigravity/scratch/NetInsight-X/docs/IEEE_Report.md)
* **Architecture Overview**: [`docs/Architecture.md`](file:///C:/Users/raghu/.gemini/antigravity/scratch/NetInsight-X/docs/Architecture.md)
* **Security & Production Posture**: [`SECURITY.md`](file:///C:/Users/raghu/.gemini/antigravity/scratch/NetInsight-X/SECURITY.md)
* **Technical Audit Verification**: [`netinsight_technical_verification_report.md`](file:///C:/Users/raghu/.gemini/antigravity/brain/7c675f8d-bce6-45db-b56e-7545fa72b331/netinsight_technical_verification_report.md)
