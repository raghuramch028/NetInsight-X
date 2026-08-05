import json
import logging
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from netinsight.config import settings

logger = logging.getLogger(__name__)

# Target Features:
# 1. packet_size (Average Packet Size)
# 2. protocol (numerical: TCP=6, UDP=17, ICMP=1, other=0)
# 3. latency (Flow duration per packet RTT)
# 4. packet_rate (Packets per second)
# 5. conn_frequency (Connection density)
FEATURE_COLUMNS = ["packet_size", "protocol", "latency", "packet_rate", "conn_frequency"]

CLASS_LABELS = {
    0: "Normal",
    1: "DoS",
    2: "DDoS",
    3: "Brute Force",
    4: "Reconnaissance",
    5: "Mirai",
    6: "Other Attacks"
}

# Mirror URL of preprocessed intrusion dataset subset (approx 2.8MB)
DATASET_URL = "https://raw.githubusercontent.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning/main/data/CICIDS2017_sample_km.csv"

def _model_paths() -> tuple[Path, Path, Path]:
    model_path = Path(settings.SVM_MODEL_PATH)
    return model_path, model_path.parent / "scaler.joblib", model_path.parent

def _metrics_path() -> Path:
    return Path(settings.SVM_MODEL_PATH).parent / "svm_model_metrics.json"

def download_dataset(data_dir: Path) -> Path:
    """Downloads the real intrusion detection sample CSV if not present locally."""
    data_dir.mkdir(parents=True, exist_ok=True)
    target_csv = data_dir / "CICIDS2017_sample_km.csv"

    if not target_csv.exists():
        logger.info(f"Downloading real intrusion detection dataset sample from: {DATASET_URL}...")
        try:
            # Add user agent to avoid blocking
            req = urllib.request.Request(
                DATASET_URL,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req) as response, open(target_csv, 'wb') as out_file:
                out_file.write(response.read())
            logger.info(f"Successfully downloaded dataset to {target_csv}")
        except Exception as e:
            logger.error(f"Failed to download dataset: {e}")
            raise e
    else:
        logger.info(f"Dataset already exists locally at {target_csv}")

    return target_csv

def preprocess_intrusion_data(csv_path: Path) -> pd.DataFrame:
    """Loads and translates raw intrusion detection columns into NetInsight features."""
    logger.info(f"Preprocessing dataset: {csv_path}...")
    df_raw = pd.read_csv(csv_path)

    # Standardize column names (strip trailing/leading spaces)
    df_raw.columns = [c.strip() for c in df_raw.columns]

    df = pd.DataFrame()

    # 1. Feature: packet_size -> mapped to 'Average Packet Size' or 'Fwd Packet Length Mean'
    if "Average Packet Size" in df_raw.columns:
        df["packet_size"] = df_raw["Average Packet Size"].astype(float)
    elif "Fwd Packet Length Mean" in df_raw.columns:
        df["packet_size"] = df_raw["Fwd Packet Length Mean"].astype(float)
    else:
        df["packet_size"] = df_raw["Avg Fwd Segment Size"].astype(float)

    # 2. Feature: protocol -> mapped from Protocol, fallback to destination port heuristics or 6.0
    if "Protocol" in df_raw.columns:
        df["protocol"] = df_raw["Protocol"].astype(float)
    elif "Destination Port" in df_raw.columns:
        def map_proto_by_port(port):
            if port in [53, 123, 1900, 5353]:
                return 17.0 # UDP
            return 6.0 # TCP
        df["protocol"] = df_raw["Destination Port"].apply(map_proto_by_port)
    else:
        df["protocol"] = 6.0

    # 3. Feature: latency -> derived from Flow Duration / (Total Packets + 1)
    fwd_pkts = df_raw.get("Total Fwd Packets", 1)
    bwd_pkts = df_raw.get("Total Backward Packets", 0)
    total_pkts = fwd_pkts + bwd_pkts
    # Duration in microseconds -> convert to seconds
    flow_duration = df_raw.get("Flow Duration", 1000.0) / 1e6
    df["latency"] = flow_duration / (total_pkts + 1.0)

    # 4. Feature: packet_rate -> mapped to 'Flow Packets/s' or 'Fwd Packets/s'
    if "Flow Packets/s" in df_raw.columns:
        # Handle potential infinite or NaN values in rate calculations
        raw_rates = df_raw["Flow Packets/s"]
        raw_rates = pd.to_numeric(raw_rates, errors="coerce").fillna(0.0)
        df["packet_rate"] = raw_rates.clip(upper=10000.0)
    else:
        df["packet_rate"] = (total_pkts / (flow_duration + 0.001)).clip(upper=10000.0)

    # 5. Feature: conn_frequency -> mapped to connections density (modeled from destination ports or local statistics)
    if "Destination Port" in df_raw.columns:
        # Map connection frequency by destination port density categories
        def map_conn_density(port):
            # Admin ports or scanner-heavy ports have higher density indicators
            if port in [80, 443]:
                return 5.0 # Normal high traffic
            if port in [22, 23, 445, 3389]:
                return 12.0 # Threat targeting
            return 2.0 # Scant or local
        df["conn_frequency"] = df_raw["Destination Port"].apply(map_conn_density)
    else:
        df["conn_frequency"] = 2.0

    # 6. Target Labels mapping
    labels = []
    raw_labels = df_raw["Label"].tolist() if "Label" in df_raw.columns else []

    for _idx, raw_label in enumerate(raw_labels):
        # Support numeric labels directly
        try:
            val = int(float(raw_label))
            if 0 <= val <= 6:
                labels.append(val)
                continue
        except (ValueError, TypeError):
            pass

        label_str = str(raw_label).upper().strip()

        if "BENIGN" in label_str or "NORMAL" in label_str:
            labels.append(0)  # Normal
        elif "DOS" in label_str and "DDOS" not in label_str:
            labels.append(1)  # DoS
        elif "DDOS" in label_str:
            labels.append(2)  # DDoS
        elif "BRUTE" in label_str or "SSH" in label_str or "TELNET" in label_str:
            labels.append(3)  # Brute Force
        elif "SCAN" in label_str or "PORT" in label_str or "RECON" in label_str:
            labels.append(4)  # Reconnaissance
        elif "MIRAI" in label_str or "BOTNET" in label_str:
            labels.append(5)  # Mirai
        else:
            labels.append(6)  # Other Attacks

    df["label"] = labels
    return df

def oversample_data(X, y, target_count=3000):  # noqa: N803
    """Oversamples minority classes in X and y array formats to target_count."""
    unique_labels, counts = np.unique(y, return_counts=True)
    X_new, y_new = [], []
    for label in unique_labels:
        idx = np.where(y == label)[0]
        X_group = X[idx]
        y_group = y[idx]
        if len(X_group) < target_count:
            # Sample with replacement
            indices = np.random.RandomState(42).choice(len(X_group), size=target_count, replace=True)
            X_new.append(X_group[indices])
            y_new.append(y_group[indices])
        else:
            X_new.append(X_group)
            y_new.append(y_group)
    return np.vstack(X_new), np.concatenate(y_new)

def train_and_save_model(data_dir_str: str | None = None) -> dict:
    """Runs the full model training pipeline on the real intrusion dataset."""
    model_path, scaler_path, model_dir = _model_paths()
    model_dir.mkdir(parents=True, exist_ok=True)

    # 1. Download & Ingest Dataset
    data_path = Path(data_dir_str or "data")
    try:
        csv_path = download_dataset(data_path)
        df = preprocess_intrusion_data(csv_path)
    except Exception as e:
        logger.error(f"Failed to ingest dataset: {e}. Cannot train SVM.", exc_info=True)
        return {}

    # Drop any NaNs
    df = df.dropna()

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    # Balanced sampling: Keep all Normal samples, cap attack classes proportionally
    # Target: ~60% Normal, ~40% Attacks (reflects real-world traffic distribution)
    normal_mask = y == 0
    attack_mask = ~normal_mask
    normal_count = int(normal_mask.sum())

    X_normal = X[normal_mask]
    y_normal = y[normal_mask]
    X_attack = X[attack_mask]
    y_attack = y[attack_mask]

    # Cap total attack samples to 2/3 of Normal count (ensures 60/40 split)
    max_attack_total = int(normal_count * 0.67)
    if len(X_attack) > max_attack_total:
        rng = np.random.RandomState(42)
        attack_indices = rng.choice(len(X_attack), size=max_attack_total, replace=False)
        X_attack = X_attack[attack_indices]
        y_attack = y_attack[attack_indices]

    X = np.vstack([X_normal, X_attack])
    y = np.concatenate([y_normal, y_attack])

    logger.info(f"Training set composition: {int(normal_count)} Normal + {len(y_attack)} Attack samples = {len(y)} total")

    # Stratify split to ensure balanced classes in validation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 2. Standardize Features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    logger.info("Training XGBoost Classifier on real intrusion traffic data...")
    clf = XGBClassifier(
        n_estimators=250,
        max_depth=9,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42
    )
    # Use class_weight via sample_weight for balanced learning
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
    clf.fit(X_train_scaled, y_train, sample_weight=sample_weights)

    # 4. Evaluate Performance
    y_pred = clf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(
        y_test,
        y_pred,
        labels=sorted(CLASS_LABELS.keys()),
        target_names=[CLASS_LABELS[i] for i in sorted(CLASS_LABELS.keys())],
        output_dict=True,
        zero_division=0
    )

    logger.info(f"XGBoost Model successfully trained! Validation Accuracy: {acc * 100:.2f}%")

    # 5. Persist Model and Scaler
    joblib.dump(clf, str(model_path))
    joblib.dump(scaler, str(scaler_path))

    # Save metrics JSON for dashboard display
    metrics = {
        "accuracy": float(acc) * 100.0,
        "precision": float(report["macro avg"]["precision"]) * 100.0,
        "recall": float(report["macro avg"]["recall"]) * 100.0,
        "f1_score": float(report["macro avg"]["f1-score"]) * 100.0,
        "kernel": "XGBoost",
        "features": ", ".join(FEATURE_COLUMNS),
        "training_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset_info": "CICIDS2017 Real Sample Subset",
        "confusion_matrix": cm.tolist(),
        "report": report,
    }

    metrics_path = _metrics_path()
    try:
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Model metrics saved to {metrics_path}")
    except Exception as e:
        logger.error(f"Failed to save model metrics: {e}")

    return metrics

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_and_save_model()
