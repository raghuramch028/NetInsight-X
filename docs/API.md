# NetInsight-X API Documentation

This document describes the modules, classes, and methods exposed within the NetInsight-X architecture.

---

## 1. Capture Module (`netinsight/capture`)

### 1.1 `PacketParser` (in `parser.py`)
Parses raw Scapy packets and extracts IP fields, performing passive approximations of network characteristics.

* **Methods:**
  * `__init__()`: Initializes the internal SYN trackers, sequence checkers, and rolling delay arrays.
  * `parse(packet: Packet) -> dict | None`: Decodes a Scapy packet. Returns a dictionary containing source/destination IPs, ports, protocol, packet size, timestamp, TTL, and estimation flags (`latency_est`, `is_retransmission`), or `None` if the packet does not have an IP layer.
  * `get_average_inter_packet_delay() -> float`: Returns the rolling average inter-packet arrival delay (fallback latency approximation).
  * `get_estimated_loss_rate() -> float`: Returns the estimated percentage packet loss computed from TCP sequence duplicate retransmissions.

### 1.2 `LiveMonitor` (in `monitor.py`)
Spawns background threads to capture network packets or run a simulated traffic replay loop, saving packets and calculating windowed metrics.

* **Methods:**
  * `__init__()`: Sets up the thread-safe packet queue and resets capture counts.
  * `start()`: Initializes database tables and starts two background daemon threads (`LiveSniffer`/`DemoReplay` and `WriterWorker`).
  * `stop()`: Halts the sniffing loops and database writing tasks, waiting for threads to join.
  * `packet_callback(packet)`: Scapy sniffer callback that queues packets.
  * `run_live_sniffer()`: Sniffer loop executor.
  * `run_demo_replay()`: Simulation loop executor for Demonstration Mode.
  * `run_writer_worker()`: Worker consuming from the queue, batch-inserting into SQLite, and recording windowed metrics to `metrics` and `state_history` tables every 2 seconds.
  * `get_capture_rate() -> float`: Returns the percentage of successfully queued packets relative to total processed packets.

---

## 2. Analytics Module (`netinsight/analytics`)

### 2.1 `AnalyticsEngine` (in `engine.py`)
Computes network throughput, device statistics, and historical metrics by querying the SQLite database and processing arrays via Pandas.

* **Methods:**
  * `get_latest_metrics() -> dict`: Fetches the most recent entry from the `metrics` table. Returns fallback defaults if the table is empty.
  * `get_historical_metrics(limit: int = 100) -> pd.DataFrame`: Returns a chronological Pandas DataFrame of metrics logs.
  * `get_protocol_distribution(window_seconds: float = 60.0) -> pd.DataFrame`: Computes packet/byte counts and percentages for TCP, UDP, and ICMP.
  * `get_top_consumers(limit: int = 5, window_seconds: float = 60.0) -> pd.DataFrame`: Identifies top source IP addresses by byte count.
  * `get_active_devices_count(window_seconds: float = 300.0) -> int`: Returns the count of unique source IPs seen.
  * `get_general_summary(window_seconds: float = 60.0) -> dict`: Returns total packets, total bytes, average packet size, and active devices count.

---

## 3. Optimization Module (`netinsight/optimization`)

### 3.1 `BandwidthOptimizer` (in `solver.py`)
Formulates and solves the linear programming bandwidth allocation problem under total link limits and QoS minimums.

* **Methods:**
  * `solve_allocation(priorities, min_bounds, max_bounds, total_capacity) -> dict`: Scales parameters dynamically to prevent numerical issues and executes `cvxopt.solvers.lp`. Performs KKT verification on the scaled parameters. Returns a dictionary containing status, allocations in bps, utility, and KKT verification indicators.
  * `_fallback_allocation(priorities, min_bounds, max_bounds, total_capacity, status) -> dict`: Proportional allocation fallback scheme executed when the LP is infeasible (sum of minimum requirements > total capacity).

### 3.2 `KKTVerifier` (in `kkt.py`)
Numerical verification class testing solver outputs against standard Karush-Kuhn-Tucker optimality criteria.

* **Methods:**
  * `verify(c, G, h, x, z) -> dict`: Checks Primal Feasibility, Dual Feasibility, Complementary Slackness, and Stationarity gradient conditions. Returns maximum residuals and pass/fail indicators.

---

## 4. Prediction Module (`netinsight/prediction`)

### 4.1 `MarkovPredictor` (in `markov.py`)
Calculates operational network states (NORMAL, BUSY, CONGESTED, FAILURE) and estimates state transition probabilities.

* **Methods:**
  * `classify_state(util, loss) -> str`: Maps bandwidth utilization and loss ratios to state labels.
  * `estimate_transition_matrix() -> np.ndarray`: Evaluates transitions in `state_history` table to return a row-stochastic 4x4 probability matrix.
  * `predict_state_distribution(current_state, k_steps) -> dict`: Computes $s^{(t+k)} = s^{(t)} P^k$.

### 4.2 `MDPRecommendationEngine` (in `mdp.py`)
Computes advisory recommendations using action-dependent transition matrices and configurable rewards via Value Iteration.

* **Methods:**
  * `solve_value_iteration() -> tuple`: Iteratively updates state values to converge on optimal policies.
  * `get_recommendation(current_state_name) -> dict`: Looks up optimal actions (Reallocate Bandwidth, Reroute Traffic, Prioritize Critical Services) and returns expected value estimates.

---

## 5. Traffic Classification Module (`netinsight/classification`)

### 5.1 `train_and_save_model` (in `train.py`)
Runs the preprocessing, scaling, and training pipelines to save trained SVM parameters.

* **Features mapped:** Packet Size, Protocol, Latency, Packet Rate, Connection Frequency.
* **Algorithm:** Support Vector Machine (SVC) with RBF Kernel.

### 5.2 `TrafficClassifier` (in `classifier.py`)
Performs classification inference on incoming packets.

* **Methods:**
  * `load_model() -> bool`: Loads the saved SVM joblib model and features scaler.
  * `update_ip_cache(src_ip, dst_ip, size, timestamp) -> tuple`: Maintains in-memory packet rates and unique connection destination frequencies.
  * `classify_packet(packet_dict) -> str`: Runs model predictions, falling back to rule-based heuristics if the SVM files are missing.
