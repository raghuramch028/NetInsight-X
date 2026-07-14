# System Architecture - NetInsight-X

NetInsight-X implements a layered architecture designed to isolate responsibilities, support multi-threaded concurrent workloads, and expose clean programmatic interfaces.

```
                  +----------------------------------+
                  |        Presentation Layer        |
                  |     (Django, Chart.js, HTML5)    |
                  +-----------------+----------------+
                                    |
                  +-----------------v----------------+
                  |          Decision Layer          |
                  |     (Markov Decision Process)    |
                  +-----------------+----------------+
                                    |
                  +-----------------v----------------+
                  |        Intelligence Layer        |
                  |   (Markov Chain, SVM Classifier) |
                  +-----------------+----------------+
                                    |
                  +-----------------v----------------+
                  |        Optimization Layer        |
                  |    (CVXOPT Linear Programming)   |
                  +-----------------+----------------+
                                    |
                  +-----------------v----------------+
                  |         Analytics Layer          |
                  |     (Pandas Analytics Engine)    |
                  +-----------------+----------------+
                                    |
                  +-----------------v----------------+
                  |          Storage Layer           |
                  |             (SQLite)             |
                  +-----------------+----------------+
                                    |
                  +-----------------+----------------+
                  |       Packet Capture Layer       |
                  |         (Scapy Thread)           |
                  +----------------------------------+
```

---

## 1. Packet Capture Layer

The **Packet Capture Layer** runs as a separate background component in Python. It captures raw ethernet/IP frames, decodes headers, and calculates passive performance estimates.

### Concurrency and Thread Safety
To prevent UI freeze or frame loss, capture operations utilize a **Producer-Consumer** architecture:

```
               [ Network Interface ]
                         |
                 ( Scapy Sniffer )
                         |
           ( Parser & Metric Estimator )
                         |
                         v
            +--------------------------+
            |    Thread-Safe Queue     |   [ Producer Thread ]
            |       (queue.Queue)      |
            +------------+-------------+
                         |
                         v
             ( Database Writer Worker )    [ Consumer Thread ]
                         |
                         +---> [ SQL inserts (packets, active_devices) ]
                         |
                         +---> [ Metric Calculation (every 2.0s) ]
                                 |
                                 +---> [ save_metric() ]
                                 +---> [ save_state_history() ]
```

- **Sniffer Thread:** Runs `scapy.all.sniff()` continuously on the specified interface. On each packet arrival, the callback extracts IP headers, estimates latency, and immediately places the record into the queue.
- **Consumer Thread:** Collects records from the queue, aggregates metrics over a sliding window (default: 2 seconds), and performs batch inserts into the database.

---

## 2. Demonstration / Replay Mode
When active capture is disabled (`settings.DEMO_MODE = True`), the Sniffer thread transitions to a generator that simulates network packets. It generates statistical packet patterns matching distinct network congestion states (Normal, Busy, Congested, Failure) to validate downstream analytics, predictors, and optimizer code paths.

---

## 3. Security, Configuration, and Observability

* **Environment-driven configuration:** `DJANGO_SECRET_KEY`, `DEBUG`, `ALLOWED_HOSTS`, `NETINSIGHT_DB_PATH`, `NETINSIGHT_SVM_PATH`, `NETINSIGHT_DEMO_MODE`, and `NETINSIGHT_LOG_LEVEL` are read from the environment at startup, making the project deployable on Render and similar PaaS platforms without editing source files.
* **Static file serving:** WhiteNoise serves collected static files in production; `python manage.py collectstatic --noinput` is part of the standard build flow.
* **Structured logging:** A `LOGGING` dictionary routes `netinsight`, `django`, and `matplotlib` loggers through a single console handler. `print()` statements in backend modules have been replaced with `logging` calls.
* **Thread safety and resource cleanup:** The capture pipeline uses a bounded `queue.Queue`, `threading.Lock` for shared window counters and caches, and `with` blocks around database connections to prevent connection leaks.
* **Graceful degradation:** If the SVM model is missing, the classifier falls back to deterministic heuristics; if the CVXOPT solver reports infeasibility, a proportional fallback allocation is returned with KKT indicators set to `False`.
