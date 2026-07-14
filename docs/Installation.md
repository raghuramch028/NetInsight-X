# Installation and Execution Guide - NetInsight-X

This document outlines the setup, dependency installation, and running instructions for NetInsight-X.

---

## 1. Prerequisites

### Windows System (Target Environment)
1. **Python 3.10+** (verified with Python 3.10.12).
2. **Npcap** or **WinPcap**:
   * Scapy requires packet capturing libraries to interface with network adapters.
   * Download and install **[Npcap](https://npcap.com/)**.
   * Make sure to check the box: *"Install Npcap in WinPcap API-compatible Mode"* during installation.
3. **Elevated Privileges (Administrator)**:
   * Capturing raw LAN sockets on Windows requires Administrator privileges.
   * Open your command prompt (cmd) or PowerShell as **Administrator**.

### Linux / macOS Systems (Reference Only)
* **Linux:** Install `libpcap-dev` via package manager (`sudo apt install libpcap-dev`) and run scripts with `sudo` or grant capabilities to Python: `sudo setcap cap_net_raw,cap_net_admin=eip /path/to/python`.
* **macOS:** Install `libpcap` (usually pre-installed, or via Homebrew) and run as root (`sudo`).

---

## 2. Setup and Installation

1. **Clone or Extract the Project:**
   Ensure the directory structure matches the layout.

2. **Initialize a Virtual Environment:**
   Run from the project root directory:
   ```bash
   python -m venv venv
   ```

3. **Activate the Virtual Environment:**
   * **Linux / macOS:**
     ```bash
     source venv/bin/activate
     ```
   * **PowerShell (Windows):**
     ```powershell
     .\venv\Scripts\Activate.ps1
     ```
   * **Command Prompt (Windows):**
     ```cmd
     .\venv\Scripts\activate.bat
     ```

4. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **(Optional) Regenerate the SVM model files:**
   ```bash
   python -m netinsight.classification.train
   ```

6. **Collect static files (required for `DEBUG=False`):**
   ```bash
   python manage.py collectstatic --noinput
   ```

---

## 3. Training the SVM Classifier (Optional)

A pre-trained SVM model is normally loaded by the classifier. To retrain the SVM classifier on official UNSW-NB15 files:
1. Download `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` from the official UNSW Canberra website.
2. Place them in a folder called `data/` at the workspace root.
3. Run the training script:
   ```powershell
   python -m netinsight.classification.train
   ```
*If data files are missing, the script automatically falls back to generating a high-quality synthetic training dataset to train and save the SVM model files (`svm_model.joblib` and `scaler.joblib`) so the system is immediately runnable.*

---

## 4. Running the Application

### Step 1: Initialize Database Migrations
Configure SQLite databases for Django:
```bash
python manage.py migrate
```
*(Note: NetInsight-X uses raw SQLite interfaces for background capture and Django ORM/raw SQL for rendering, using the same unified database file configured in `netinsight/config/settings.py`)*

### Step 2: Start the Django Server
Run the command in your elevated terminal (Administrator on Windows, or `sudo`/capable user on Linux/macOS):
```bash
python manage.py runserver
```

### Step 3: Access the Dashboard
Open your browser and navigate to:
**[http://localhost:8000/](http://localhost:8000/)**

The background thread starts lazily on the first request to poll packets and calculate metrics.
To configure the sniff interface, link capacities, or prediction state thresholds, see **[Configuration.md](Configuration.md)**.  
To switch off simulated/replay traffic and sniff live local traffic, set `NETINSIGHT_DEMO_MODE=False` in the environment or change `DEMO_MODE` to `False` in `netinsight/config/settings.py`.
