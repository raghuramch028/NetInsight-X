import os
import joblib
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

logger = logging.getLogger(__name__)

from netinsight.config import settings

# Constants
MODEL_PATH = Path(settings.SVM_MODEL_PATH)
SCALER_PATH = MODEL_PATH.parent / "scaler.joblib"
MODEL_DIR = MODEL_PATH.parent

# Feature definitions
# 1. Packet Size (sbytes)
# 2. Protocol (numerical: TCP=6, UDP=17, ICMP=1, other=0)
# 3. Latency (rtt or dur)
# 4. Packet Rate (rate)
# 5. Connection Frequency (ct_srv_src)
FEATURE_COLUMNS = ["packet_size", "protocol", "latency", "packet_rate", "conn_frequency"]
CLASS_LABELS = {
    0: "Web Browsing",
    1: "Streaming",
    2: "File Transfer",
    3: "Potentially Suspicious"
}

def generate_synthetic_unsw_data(n_samples: int = 2000) -> pd.DataFrame:
    """Generates synthetic network data mirroring the mapped UNSW-NB15 schema.
    
    Used for testing, local execution fallback, and demonstrations.
    """
    logger.info("Generating representative synthetic traffic classification training data...")
    np.random.seed(42)
    
    data = []
    for _ in range(n_samples):
        # Choose class label
        # 0 = Web Browsing, 1 = Streaming, 2 = File Transfer, 3 = Potentially Suspicious
        label = np.random.choice([0, 1, 2, 3], p=[0.40, 0.25, 0.20, 0.15])
        
        if label == 0:  # Web Browsing
            packet_size = float(np.random.randint(200, 1500))
            protocol = 6.0  # TCP
            latency = float(np.random.uniform(0.005, 0.030))
            packet_rate = float(np.random.uniform(2.0, 30.0))
            conn_frequency = float(np.random.randint(1, 10))
        elif label == 1:  # Streaming
            packet_size = float(np.random.randint(1200, 1500))
            protocol = 17.0  # UDP (mostly video)
            latency = float(np.random.uniform(0.015, 0.050))
            packet_rate = float(np.random.uniform(80.0, 300.0))
            conn_frequency = float(np.random.randint(10, 40))
        elif label == 2:  # File Transfer
            packet_size = float(np.random.randint(1400, 1500))
            protocol = 6.0  # TCP
            latency = float(np.random.uniform(0.020, 0.080))
            packet_rate = float(np.random.uniform(50.0, 200.0))
            conn_frequency = float(np.random.randint(1, 5))
        else:  # Potentially Suspicious (scans, flood, high jitter)
            packet_size = float(np.random.randint(40, 1000))
            protocol = float(np.random.choice([6.0, 17.0, 1.0])) # TCP, UDP, or ICMP
            latency = float(np.random.uniform(0.100, 0.600))     # High latency spikes
            packet_rate = float(np.random.uniform(500.0, 2000.0)) # Massive attack rates
            conn_frequency = float(np.random.randint(80, 200))   # High service hit counts
            
        data.append([packet_size, protocol, latency, packet_rate, conn_frequency, label])
        
    df = pd.DataFrame(data, columns=FEATURE_COLUMNS + ["label"])
    return df

def load_official_unsw_dataset(train_csv_path: str, test_csv_path: str) -> pd.DataFrame:
    """Loads and preprocesses official UNSW-NB15 CSV datasets from a local path.
    
    Performs feature engineering and maps binary/attack classes to target application classes.
    """
    logger.info(f"Loading official UNSW-NB15 CSVs: {train_csv_path}, {test_csv_path}")
    
    df_train = pd.read_csv(train_csv_path)
    df_test = pd.read_csv(test_csv_path)
    df_raw = pd.concat([df_train, df_test], ignore_index=True)
    
    # Preprocessing feature mapping:
    # - packet_size = sbytes (source bytes)
    # - protocol = numeric mapping of proto (TCP=6, UDP=17, ICMP=1, others=0)
    # - latency = dur (duration) or rtt (if available)
    # - packet_rate = rate (packet rate)
    # - conn_frequency = ct_srv_src (connection frequency)
    
    df = pd.DataFrame()
    df["packet_size"] = df_raw["sbytes"].astype(float)
    
    # Protocol mapping
    def map_proto(p):
        p_lower = str(p).lower()
        if "tcp" in p_lower: return 6.0
        if "udp" in p_lower: return 17.0
        if "icmp" in p_lower: return 1.0
        return 0.0
    df["protocol"] = df_raw["proto"].apply(map_proto)
    
    df["latency"] = df_raw["dur"].astype(float)
    df["packet_rate"] = df_raw["rate"].astype(float)
    df["conn_frequency"] = df_raw["ct_srv_src"].astype(float)
    
    # --- Class Label Mapping ---
    # Normal and Malicious split:
    # - If raw label == 1 (Attack) -> Mapped to 'Potentially Suspicious' (3)
    # - If raw label == 0 (Normal) -> Map to application category based on service and size
    labels = []
    raw_labels = df_raw["label"].tolist()
    raw_services = df_raw["service"].tolist()
    raw_rates = df_raw["rate"].tolist()
    raw_sizes = df_raw["sbytes"].tolist()
    
    for idx in range(len(df_raw)):
        if raw_labels[idx] == 1:
            labels.append(3)  # Potentially Suspicious
        else:
            srv = str(raw_services[idx]).lower()
            if srv in ["http", "ssl", "dns", "dhcp"]:
                labels.append(0)  # Web Browsing
            elif srv in ["ftp", "ftp-data"] or raw_sizes[idx] > 50000:
                labels.append(2)  # File Transfer
            elif raw_rates[idx] > 50.0 and raw_sizes[idx] > 10000:
                labels.append(1)  # Streaming
            else:
                labels.append(0)  # Default normal is Web Browsing
                
    df["label"] = labels
    return df

def train_and_save_model(data_dir: str = None) -> dict:
    """Trains the RBF Kernel SVM model and saves it along with the scaler."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    train_file = None
    test_file = None
    
    if data_dir:
        path = Path(data_dir)
        train_cand = path / "UNSW_NB15_training-set.csv"
        test_cand = path / "UNSW_NB15_testing-set.csv"
        if train_cand.exists() and test_cand.exists():
            train_file = str(train_cand)
            test_file = str(test_cand)
            
    if train_file and test_file:
        df = load_official_unsw_dataset(train_file, test_file)
    else:
        logger.warning(
            "Official local UNSW-NB15 dataset CSV files not found. "
            "To train on official data, download the training and testing sets from UNSW Canberra "
            "and place them in a local 'data/' directory. Falling back to synthetic training set."
        )
        df = generate_synthetic_unsw_data()

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Standardize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train RBF Kernel SVM
    # Network traffic data boundaries are non-linear; RBF kernel projects features into high dimensional space
    logger.info("Training RBF Kernel Support Vector Machine...")
    clf = SVC(kernel="rbf", C=1.0, gamma="scale", random_state=42)
    clf.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=[CLASS_LABELS[i] for i in sorted(CLASS_LABELS.keys())], output_dict=True)

    logger.info(f"Model trained. Validation Accuracy: {acc:.4f}")

    # Save to disk
    joblib.dump(clf, str(MODEL_PATH))
    joblib.dump(scaler, str(SCALER_PATH))
    logger.info(f"Model and scaler saved to {MODEL_DIR}")

    return {
        "accuracy": acc,
        "confusion_matrix": cm.tolist(),
        "report": report
    }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_and_save_model()
