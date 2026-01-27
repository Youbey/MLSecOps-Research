# Federated Learning Docker Setup - Complete Guide

## Project Structure

```
fl-project/
├── Dockerfile
├── docker-compose.yml
├── prometheus.yml
├── requirements.txt
├── server.py           # FL Server
├── client.py           # FL Client
├── control.py          # Control & monitoring tool
├── generate_data.py    # Data generation script
└── data/               # Client training data
    ├── client_1_data.json
    └── client_2_data.json
```

## Quick Start

### 1. Generate Training Data

```bash
python generate_data.py
```

Creates synthetic word prediction data for both clients (200 samples each).

### 2. Build & Start Containers

```bash
docker-compose up --build
```

This starts:
- **FL Server** (port 5000): Aggregates model updates
- **Client 1** (container): Trains on client_1_data.json
- **Client 2** (container): Trains on client_2_data.json
- **Prometheus** (port 9090): Metrics collection

You should see logs like:
```
fl_server | Starting FL Server on port 5000
fl_client_1 | Client client_1 initialized
fl_client_2 | Client client_2 initialized
fl_client_1 | >>> Cycle 1
```

### 3. Control Training (In Another Terminal)

```bash
# Check server status
python control.py --mode status

# Automated training: 5 rounds, wait 15s each for client updates
python control.py --mode train --rounds 5 --wait 15

# Manual trigger (after verifying updates arrived)
python control.py --mode trigger

# Continuous monitoring
python control.py --mode monitor --interval 5
```

---

## How the System Works

1. Runs federated learning cycles with benign and malicious clients
2. Detects attacks in real-time via the FL server
3. Collects logs (Loki) and metrics (Prometheus)
4. Visualizes data in Grafana dashboards
5. Generates security audit reports

### **Step 1: Jenkins Pipeline Triggers (Jenkinsfile)**
```
User/Scheduler → Jenkins triggers with parameters:
├── ATTACK_MODE: Choose which attack to test (POISONING, STEALTHY, etc.)
├── FL_ROUNDS: Number of federated learning training rounds
├── FL_WAIT: Time between rounds (allows convergence)
└── RUN_SECURITY_AUDIT: Enable/disable security analysis
```

### **Step 2: Code Quality & Build Stage**
```
1. Code scanning (Bandit, Semgrep) for vulnerabilities
2. Docker images built ONCE (reused for all attacks)
3. Containers spun up: FL server + honest clients + malicious client
```

### **Step 3: Data Preparation**
```
fetch_and_split.py runs:
- Downloads/generates training data (MNIST, CIFAR, etc.)
- Splits into client_1_data.json, malicious_client_data.json
- Stored in ./data/ volume (shared across containers)
```

### **Step 4: Attack Scenario Execution**
```
Control flow (control.py runs inside fl_server container):
├── Round N:
│   ├── Malicious client submits poisoned gradients
│   ├── Honest clients submit clean gradients
│   ├── Server aggregates all updates
│   ├── Server runs security analysis:
│   │   ├── Gradient anomaly detection
│   │   ├── Poisoning detection
│   │   ├── Byzantine detection
│   │   └── Sybil detection
│   ├── Malicious updates REJECTED
│   ├── Aggregation updated with only honest updates
│   ├── Results logged to security_audits/round_N.json
│   └── Audit logs sent to Loki
└── Repeat for next round
```

### **Step 5: Logging Pipeline (Loki)**
```
All containers configured with loki logging driver:

Container logs:
fl_server        ──┐
fl_client_1      ──┼──→ Loki (3100) ──→ Stored as time-series labeled data
fl_malicious     ──┤    └─ Job labels by container
fl_prometheus    ──┘
fl_grafana

Loki stores:
- Container ID, job name (fl_server, fl_client)
- Full log text with timestamps
- Allows querying like: {job="fl_server"} | json | level="ERROR"
```

### **Step 6: Metrics Collection (Prometheus)**
```
Prometheus (9091) scrapes from FL server's /metrics endpoint every 15 seconds:

Server exposes:
├── fl_training_rounds (counter) - Total rounds completed
├── fl_model_accuracy (gauge) - Current model accuracy
├── fl_poisoned_updates_detected (counter) - Attacks detected
├── fl_cpu_usage (gauge)
├── fl_memory_usage (gauge)
└── Request latency metrics

Stored in: /prometheus volume (TSDB - Time Series Database)
```

### **Step 7: Grafana Visualization**
```
Grafana (3000) connects to:
├── Prometheus data source
│   └── Queries metrics from Prometheus TSDB
│   └── Creates graphs: Accuracy over time, Attack detection rate
│
└── Loki data source
    └── Queries logs with labels
    └── Shows audit trails, error messages with timestamps
```

### **Step 8: Security Analysis & Reporting**
```
After all rounds complete:
1. Python script reads all security_audits/*.json files
2. Aggregates:
   ├── Total attacks detected & rejected
   ├── Per-client statistics (accepted/rejected)
   └── Attack type distribution
3. Generates HTML report (Jenkins publishHTML)
4. Archives as Jenkins artifacts
```

