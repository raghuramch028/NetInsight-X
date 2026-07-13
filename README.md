# NetInsight-X

**NetInsight-X: An Intelligent Decision Support System for Network Monitoring, Traffic Analytics, Optimization, and Predictive Network Management**

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
1. **Python 3.10+** (Python 3.14 was verified during development).
2. **Npcap**: Scapy requires Npcap to capture live sockets on Windows.
   * Download and install **[Npcap](https://npcap.com/)**.
   * Select *"Install Npcap in WinPcap API-compatible Mode"* during installation.
3. **Elevated Privileges (Administrator)**: Raw socket packet sniffing requires Administrator permissions on Windows. Run your terminal (cmd/PowerShell) as Administrator.

### 2.2 Quickstart Commands
From the project root folder:

```powershell
# 1. Initialize virtual environment
python -m venv venv

# 2. Activate virtual environment
# On PowerShell:
.\venv\Scripts\Activate.ps1
# On CMD:
.\venv\Scripts\activate.bat

# 3. Install requirements
pip install -r requirements.txt

# 4. Initialize Django Database
python manage.py migrate

# 5. Start Django Application
python manage.py runserver
```

Open your browser and navigate to: **[http://localhost:8000/](http://localhost:8000/)**

---

## 3. Project Configuration

Configure network monitor interfaces, link capacities, or decision weights inside **`netinsight/config/settings.py`**:
* **`CAPTURE_INTERFACE`**: Bind to a specific network adapter index (defaults to `None` to auto-detect).
* **`LINK_CAPACITY`**: Configurable bandwidth scale in bps (default: `100_000_000.0` or 100 Mbps).
* **`DEMO_MODE`**: If `True`, the capture module replays simulated packet transitions representing distinct network loads. Switch to `False` to sniff live physical interface traffic.

---

## 4. Run Diagnostic Tests

To run the complete test suite verifying all 6 modules (capture, database, analytics, optimization, prediction, classification, and views):

```powershell
.\venv\Scripts\python.exe -m unittest discover -s netinsight/tests/
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
* **SRS & Technical Report:** [IEEE_Report.md](file:///c:/Users/raghu/OneDrive/Desktop/MFC-3/docs/IEEE_Report.md)
* **Mathematical Derivations:** [Mathematical_Formulation.md](file:///c:/Users/raghu/OneDrive/Desktop/MFC-3/docs/Mathematical_Formulation.md)
* **Database Schema Layout:** [DatabaseDesign.md](file:///c:/Users/raghu/OneDrive/Desktop/MFC-3/docs/DatabaseDesign.md)
* **Programmatic APIs:** [API.md](file:///c:/Users/raghu/OneDrive/Desktop/MFC-3/docs/API.md)
