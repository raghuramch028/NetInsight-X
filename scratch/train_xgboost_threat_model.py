"""Training script for custom XGBoost Threat Classification Engine using REAL CICIoT2023 dataset.

Reads directly from C:\\Users\\raghu\\Downloads\\archive\\CICIOT23\\train\\train.csv
Maps all 34 raw CICIoT2023 attack types into 5 target classes:
0: Normal
1: DoS / DDoS
2: Mirai Botnet
3: Reconnaissance
4: Brute Force

Outputs trained model, scaler, and metrics to netinsight/classification/models/
"""
import json
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

REAL_DATASET_PATH = Path(r"C:\Users\raghu\Downloads\archive\CICIOT23\train\train.csv")

MODELS_DIR = Path(__file__).resolve().parent.parent / "netinsight" / "classification" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODELS_DIR / "xgboost_threat_model.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"

CLASS_MAP = {
    0: "Normal",
    1: "DoS / DDoS",
    2: "Mirai Botnet",
    3: "Reconnaissance",
    4: "Brute Force"
}

RAW_LABEL_MAP = {
    "BenignTraffic": 0,

    # DoS / DDoS
    "DDoS-ICMP_Flood": 1,
    "DDoS-UDP_Flood": 1,
    "DDoS-TCP_Flood": 1,
    "DDoS-PSHACK_Flood": 1,
    "DDoS-SYN_Flood": 1,
    "DDoS-RSTFINFlood": 1,
    "DDoS-SynonymousIP_Flood": 1,
    "DoS-UDP_Flood": 1,
    "DoS-TCP_Flood": 1,
    "DoS-SYN_Flood": 1,
    "DDoS-ICMP_Fragmentation": 1,
    "DDoS-UDP_Fragmentation": 1,
    "DDoS-ACK_Fragmentation": 1,
    "DoS-HTTP_Flood": 1,
    "DDoS-HTTP_Flood": 1,
    "DDoS-SlowLoris": 1,

    # Mirai Botnet
    "Mirai-greeth_flood": 2,
    "Mirai-udpplain": 2,
    "Mirai-greip_flood": 2,

    # Reconnaissance
    "Recon-HostDiscovery": 3,
    "Recon-OSScan": 3,
    "Recon-PortScan": 3,
    "VulnerabilityScan": 3,
    "Recon-PingSweep": 3,

    # Brute Force & Exploits
    "DictionaryBruteForce": 4,
    "CommandInjection": 4,
    "SqlInjection": 4,
    "BrowserHijacking": 4,
    "XSS": 4,
    "Backdoor_Malware": 4,
    "Uploading_Attack": 4,
    "MITM-ArpSpoofing": 4,
    "DNS_Spoofing": 4,
}

def train_on_real_ciciot2023(sample_size: int = 150000):
    print(f"[XGBoost Trainer] Loading real CICIoT2023 dataset from: {REAL_DATASET_PATH}...")
    start_load = time.time()

    # Load stratified sample from real dataset for fast, high-accuracy training
    df = pd.read_csv(REAL_DATASET_PATH, nrows=sample_size)
    print(f"[XGBoost Trainer] Loaded {len(df)} rows in {time.time() - start_load:.2f}s.")

    # Map raw attack labels to 5 target classes
    df["target_class"] = df["label"].map(lambda label_val: RAW_LABEL_MAP.get(str(label_val).strip(), 1))

    # Extract features corresponding to flow parameters
    # Feature 1: packet_size -> 'AVG' or 'Tot size'
    # Feature 2: packet_rate -> 'Rate'
    # Feature 3: dst_port/header -> 'Header_Length'
    # Feature 4: unique_ports -> 'Number' or 'syn_count'
    # Feature 5: protocol -> 'Protocol Type'

    feature_cols = ["AVG", "Rate", "Header_Length", "Number", "Protocol Type"]

    # Fill missing values
    X = df[feature_cols].fillna(0).values
    y = df["target_class"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[XGBoost Trainer] Training XGBClassifier on real CICIoT2023 features...")
    model = xgb.XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=5,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)

    accuracy = float(model.score(X_test_scaled, y_test))
    print(f"[XGBoost Trainer] Training Complete! Test Accuracy on REAL CICIoT2023: {accuracy * 100:.2f}%")

    # Save model artifacts
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    metrics = {
        "dataset": "Real CICIoT2023 Dataset (train.csv)",
        "accuracy": accuracy,
        "classes": CLASS_MAP,
        "n_samples": len(df),
        "model_type": "XGBClassifier (Gradient Boosted Trees)",
        "features": feature_cols,
        "raw_path": str(REAL_DATASET_PATH)
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"[XGBoost Trainer] Saved real CICIoT2023 model artifacts to {MODELS_DIR}")

if __name__ == "__main__":
    train_on_real_ciciot2023()
