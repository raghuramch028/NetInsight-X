# Changelog

All notable changes to the NetInsight-X project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-08-04
### Added
- **XGBoost Classifier Integration:** Transitioned the ML threat classification from baseline SVM to XGBoost with balanced class weights, raising validation accuracy to **91.82%**.
- **Dataset Balancing:** Implemented a pre-split `oversample_data` numpy algorithm to address minority class target sample limits (DDoS, Reconnaissance).
- **Platform-Aware Local Shaper:** Upgraded simulated shaping to execute Linux kernel `tc` (Traffic Control) token bucket filter (`tbf`) rules and Windows PowerShell QoS policies natively.
- **Continuous Integration:** Added GitHub Actions CI workflows for automated code style checks and test execution.
- **EditorConfig:** Added standardized editor configs to align spacing across developer environments.

### Fixed
- **Render Out-of-Memory Mitigations:** Reduced Gunicorn worker targets to 1 and implemented explicit figure clearing and garbage collection loops for Matplotlib graph conversions to stay under the 512MB RAM ceiling.

---

## [1.1.0] - 2026-07-26
### Added
- **Go Edge Agent (`agent_go`):** Developed a concurrent compiled Go-based edge agent utilizing Google's `gopacket` and `gopsutil` to Sniff metrics with low resource footprint.
- **Closed-Loop QoS Loop:** Integrated dynamic bandwidth constraints returned in HTTPSuccess headers for local agent rate shaping.

### Fixed
- **Retry Delay Performance:** Replaced exponential backoff loops with a flat `3.0` seconds interval on upload failures to optimize recovery.

---

## [1.0.0] - 2026-07-19
### Added
- Initial release featuring distributed Scapy-based sniffer agents, central Django telemetry views, SVM classifications, and Viterbi HMM network state forecasts.
