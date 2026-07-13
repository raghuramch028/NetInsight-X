# Mathematical Formulations - NetInsight-X

This document records the mathematical formulations, derivations, variables, and validations for NetInsight-X.

---

## 1. Packet Capture Heuristics & Metrics Approximations (Module 1)

Passive traffic capture cannot perform active measurements (like sending ping requests or traceroute queries). Therefore, it must estimate metrics using incoming traffic patterns.

### 1.1 Throughput and Packet Rate
Let $P_t = \{p_1, p_2, \dots, p_n\}$ be the set of packets captured in a time interval $[t_0, t_0 + \Delta t]$.
Let $\text{size}(p)$ represent the size of packet $p$ in bytes.

- **Throughput (bits per second):**
  $$\text{Throughput} = \frac{8 \cdot \sum_{p \in P_t} \text{size}(p)}{\Delta t}$$
  *Variables:*
  - $\Delta t$: Sniffing window interval in seconds.
  - $\text{size}(p)$: Number of bytes in packet $p$ at the Link layer.

- **Packet Rate (packets per second):**
  $$\text{Packet Rate} = \frac{|P_t|}{\Delta t}$$
  Where $|P_t|$ represents the cardinality (total count) of packet records in the window.

- **Bandwidth Utilization (%):**
  $$\text{Bandwidth Utilization} = \frac{\text{Throughput}}{\text{Link Capacity}} \times 100\%$$
  Where Link Capacity $B$ is a configurable variable in `config/settings.py` (default: 100 Mbps).

---

### 1.2 Latency (Round-Trip Time) Approximation
Passive capture estimates latency by tracking TCP handshake events or inter-packet arrival gaps.

#### Heuristic A: TCP Handshake RTT
For a TCP flow defined by the 4-tuple $F = (\text{SrcIP}, \text{SrcPort}, \text{DstIP}, \text{DstPort})$:
1. When a packet from Client to Server is observed with flags `SYN = 1` and `ACK = 0` at time $t_{\text{SYN}}$, the timestamp is saved:
   $$\tau_{\text{SYN}}(F) = t_{\text{SYN}}$$
2. When the corresponding handshake response from Server to Client with flags `SYN = 1` and `ACK = 1` is captured at time $t_{\text{SYN-ACK}}$, the Client-to-Server RTT estimate is:
   $$\text{RTT}_{\text{Client}} = t_{\text{SYN-ACK}} - \tau_{\text{SYN}}(F)$$
3. When the final `ACK` from Client to Server is captured at time $t_{\text{ACK}}$, the Server-to-Client RTT estimate is:
   $$\text{RTT}_{\text{Server}} = t_{\text{ACK}} - \tau_{\text{SYN-ACK}}(F')$$
   where $F'$ is the reverse flow 4-tuple.

#### Heuristic B: Inter-packet Delay (Fallback)
When complete TCP handshakes are unavailable (e.g. for ongoing UDP or ICMP flows), the latency is approximated using a rolling window of inter-packet gaps.
Let $t_k(F)$ be the arrival timestamp of the $k$-th packet in flow $F$.
The inter-packet delay gap is:
$$g_k(F) = t_k(F) - t_{k-1}(F)$$
The fallback latency is the arithmetic mean of these gaps across a rolling history of active flows:
$$\text{Latency}_{\text{approx}} = \frac{1}{M} \sum_{j=1}^{M} g_j$$
Where $M$ is the historical window size (default: 1000). The dashboard indicates this metric is a passive approximation.

---

### 1.3 Packet Loss Heuristic
Passive packet capture cannot directly detect packets dropped at intermediate routers. Instead, it monitors TCP sequence number anomalies.

- Let $S(F)$ be the set of TCP sequence numbers observed for flow $F$.
- When a TCP packet with sequence number $s$ and payload length $L > 0$ is received:
  - If $s \in S(F)$, the packet is classified as a **retransmission**.
  - Else, $s$ is added to $S(F)$.
- **Estimated Packet Loss (%):**
  $$\text{Estimated Packet Loss} = \frac{\text{Count of Retransmitted Packets}}{\text{Total Packets}} \times 100\%$$

---

## 2. Traffic Analytics Engine (Module 2)

The analytics engine processes historical database entries using Pandas to calculate network performance profiles.

### 2.1 Protocol Distribution
- **Formulation:**
  Let $C(P)$ be the number of packets matching protocol $P \in \{\text{TCP}, \text{UDP}, \text{ICMP}\}$ in the query window, and $C_{\text{total}}$ be the total count of packets.
  $$\text{Protocol Percentage}(P) = \frac{C(P)}{C_{\text{total}}} \times 100\%$$
- **Assumptions:**
  - Protocol information extracted from the IP header represents the actual packet payload protocol.
- **Limitations:**
  - Packets traversing encrypted tunnels (such as IPSec, OpenVPN) are classified strictly under the outer encapsulation protocol, obscuring internal application types.

### 2.2 Top Bandwidth Consumers
- **Formulation:**
  Let $B(IP)$ be the sum of sizes (in bytes) of all packets where $\text{SrcIP} = IP$ in the query window, and $B_{\text{total}}$ be the total volume of traffic in bytes.
  $$\text{Traffic Percentage}(IP) = \frac{B(IP)}{B_{\text{total}}} \times 100\%$$
- **Assumptions:**
  - Source IP addresses are authentic and have not been spoofed by malicious hosts.
- **Limitations:**
  - Multi-user gateways or NAT proxies are aggregated as a single consumer IP, hiding individual client bandwidth consumption details.

### 2.3 Average Packet Size
- **Formulation:**
  $$\bar{S} = \frac{\sum_{p \in P_t} \text{size}(p)}{|P_t|}$$
- **Assumptions:**
  - At least one packet is captured in the aggregation interval ($|P_t| > 0$).
- **Limitations:**
  - Heavily skewed by large bursts of small packets (e.g. ACK packets or DNS requests) versus large file transmissions.

---

## 3. Bandwidth Optimization & KKT Verification (Module 3)

### 3.1 Linear Programming Formulation
The bandwidth allocation is formulated as a linear programming model to maximize weighted class throughput under QoS bounds:
$$\text{Maximize } \sum_{i=1}^{N} c_i x_i$$
$$\text{Subject to } \sum_{i=1}^{N} x_i \le B$$
$$x_i \ge m_i \quad \forall i=1,\dots,N$$
$$x_i \le M_i \quad \forall i=1,\dots,N$$
*Variables:*
- $x_i \in \mathbb{R}$: Bandwidth allocation for class $i$ (decision variable).
- $c_i \in \mathbb{R}$: Priority coefficient (weight) of class $i$.
- $B \in \mathbb{R}$: Total link bandwidth capacity.
- $m_i \in \mathbb{R}$: Minimum QoS bandwidth guaranteed for class $i$.
- $M_i \in \mathbb{R}$: Maximum allowable bandwidth limit for class $i$.

**Convexity:** The objective function is linear, and the inequality constraints form a closed convex polytope. As a result, the linear program is structurally convex, ensuring that any local optimum found is the global optimum.

### 3.2 Karush-Kuhn-Tucker (KKT) Optimality Conditions
To verify the optimality of the primal-dual solution pair $(x^*, \lambda^*)$, we convert the constraints into the standard inequality form $G x \le h$.
The Lagrangian function is:
$$L(x, \lambda) = -c^T x + \lambda^T (G x - h)$$
Where $\lambda \ge 0$ is the vector of inequality Lagrange multipliers. The KKT conditions check:
1. **Primal Feasibility:** Checks constraint satisfaction:
   $$G x^* - h \le 0$$
2. **Dual Feasibility:** Checks that multiplier forces remain non-negative:
   $$\lambda^* \ge 0$$
3. **Complementary Slackness:** Asserts that inactive constraints have zero multipliers:
   $$\lambda_j^* \cdot (G x^* - h)_j = 0 \quad \forall j$$
4. **Stationarity:** The gradient of the Lagrangian relative to decision values vanishes:
   $$\nabla_x L(x^*, \lambda^*) = -c + G^T \lambda^* = 0$$

Numerical verification evaluates these conditions against a small tolerance boundary ($\epsilon = 10^{-5}$).

---

## 4. Operational State Prediction & MDP Recommendations (Module 4)

### 4.1 Markov Chain State Forecasting
Network metrics are classified into four states: Normal ($0$), Busy ($1$), Congested ($2$), and Failure ($3$).
The state transition probability matrix $P \in \mathbb{R}^{4 \times 4}$ represents the probability of moving from state $i$ to state $j$:
$$P_{ij} = P(S_{t+1} = j \mid S_t = i) = \frac{N_{ij}}{\sum_k N_{ik}}$$
Where $N_{ij}$ is the frequency count of state transition $(i \to j)$ recorded chronologically in `state_history`.
- **k-Step Ahead Forecasting:**
  $$s^{(t+k)} = s^{(t)} P^k$$
  Where $s^{(t)}$ is the one-hot encoded state probability vector at time $t$.

### 4.2 Markov Decision Process (MDP)
To recommend advisory actions $a \in \mathcal{A} = \{\text{Reallocate Bandwidth}, \text{Reroute Traffic}, \text{Prioritize Critical Services}\}$:
- **Bellman Optimality Value Iteration:**
  $$V^{(k+1)}(s) = \max_{a \in \mathcal{A}} \left[ R(s, a) + \gamma \sum_{s' \in \mathcal{S}} P_a(s' \mid s) V^{(k)}(s') \right]$$
  Where $R(s, a)$ is the configurable state-action reward, $P_a$ is the action-dependent transition matrix, and $\gamma$ is the discount factor (default: $0.90$).
- **Optimal Policy Recommendation:**
  $$a^*(s) = \arg\max_{a \in \mathcal{A}} \left[ R(s, a) + \gamma \sum_{s'} P_a(s' \mid s) V^*(s') \right]$$

---

## 5. SVM Traffic Classification (Module 5)

We deploy a **Radial Basis Function (RBF) Kernel Support Vector Machine** to map engineered packet features to traffic profile classes. Network traffic features are highly overlapping and non-linearly separable.
- **RBF Kernel mapping function:**
  $$K(x, x') = \exp(-\gamma \|x - x'\|^2)$$
- **Optimization Objective:**
  $$\min_{w, b, \xi} \frac{1}{2} \|w\|^2 + C \sum_{i=1}^{M} \xi_i$$
  $$\text{Subject to } y_i (w^T \phi(x_i) + b) \ge 1 - \xi_i, \quad \xi_i \ge 0$$
  Where $C$ is the regularization trade-off penalty, and $\xi_i$ represents training slack variables.
- **Inference vector:**
  $$X_i = [\text{Packet Size}, \text{Protocol}, \text{Latency}, \text{Packet Rate}, \text{Connection Frequency}]$$
