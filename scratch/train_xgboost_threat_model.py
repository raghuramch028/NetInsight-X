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
from pathlib import Path

import joblib
import pandas as pd
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

def train_on_preprocessed_ciciot2023():
    train_csv = MODELS_DIR / "ciciot2023_preprocessed_train.csv"
    val_csv = MODELS_DIR / "ciciot2023_preprocessed_val.csv"
    test_csv = MODELS_DIR / "ciciot2023_preprocessed_test.csv"

    feature_cols = ["AVG", "Rate", "Header_Length", "Number", "Protocol Type"]

    print(f"[XGBoost Trainer] Loading preprocessed dataset from: {train_csv}...")
    train_df = pd.read_csv(train_csv)
    X_train = train_df[feature_cols].fillna(0).values
    y_train = train_df["target_class"].values

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print(f"[XGBoost Trainer] Training XGBClassifier on {len(train_df)} rows...")
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

    train_acc = float(model.score(X_train_scaled, y_train))

    # Evaluate Validation Split
    val_df = pd.read_csv(val_csv)
    X_val_scaled = scaler.transform(val_df[feature_cols].fillna(0).values)
    val_acc = float(model.score(X_val_scaled, val_df["target_class"].values))

    # Evaluate Test Split
    test_df = pd.read_csv(test_csv)
    X_test_scaled = scaler.transform(test_df[feature_cols].fillna(0).values)
    test_acc = float(model.score(X_test_scaled, test_df["target_class"].values))

    print(f"[XGBoost Trainer] Train Accuracy: {train_acc * 100:.2f}% | Val Accuracy: {val_acc * 100:.2f}% | Test Accuracy: {test_acc * 100:.2f}%")

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    metrics = {
        "dataset": "CICIoT2023 Preprocessed Splits",
        "train_accuracy": train_acc,
        "validation_accuracy": val_acc,
        "test_accuracy": test_acc,
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "model_type": "XGBClassifier (Gradient Boosted Trees)",
        "features": feature_cols
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

if __name__ == "__main__":
    train_on_preprocessed_ciciot2023()
