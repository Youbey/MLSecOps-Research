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

### Training Cycle Flow

```
Client 1 & 2 (running continuously):
  1. FETCH: Download global model from server (round N)
  2. TRAIN: Train locally for 2 epochs on local data
  3. SUBMIT: Send updated weights to server
  4. WAIT: Sleep 5s, then repeat

Server (initially waiting):
  Receives updates from clients asynchronously
  Stores them indexed by client_id

Controller (you trigger):
  1. Monitors pending updates via /status
  2. When ready, calls /trigger_round
  3. Server aggregates all updates (federated averaging)
  4. Increments round number
  5. Clients fetch new model and cycle continues
```

### Example Timeline

```
T=0s   | Client 1 & 2 start fetching model (round 0)
T=2s   | Both clients finish training locally
T=3s   | Both clients submit updates to server
T=5s   | (Manual) python control.py --mode trigger
T=5s   | Server aggregates 2 updates → new model (round 1)
T=6s   | Clients fetch new model (round 1)
T=8s   | Training completes again
T=9s   | Submit updates
T=13s  | (Manual) trigger round 2
...
```

---

## Monitoring & Observability

### 1. **Real-time Logs**

```bash
# All logs
docker-compose logs -f

# Specific container
docker-compose logs -f fl_server
docker-compose logs -f fl_client_1
```

### 2. **Status Endpoint** (JSON)

```bash
curl http://localhost:5000/status | jq

# Response includes:
# - current round number
# - client states (samples, last update, metrics)
# - pending updates waiting for aggregation
# - recent training history
```

### 3. **Prometheus Metrics**

Access metrics at: http://localhost:9090

Key metrics:
- `fl_updates_received_total` - Count per client
- `fl_update_size_bytes` - Update payload sizes
- `fl_training_round_total` - Total aggregations done

### 4. **Control.py Monitoring Modes**

```bash
# Status snapshot
python control.py --mode status

# Live monitoring (updates every 10s)
python control.py --mode monitor --interval 10

# Automated training (waits for clients, triggers round)
python control.py --mode train --rounds 10 --wait 20
```

---

## Data Flow Monitoring

### Inspecting What's Sent

The server logs include:

```
[Server] Update from client_1: loss=0.2341, accuracy=0.8923, size=4256314 bytes
[Server] Update from client_2: loss=0.1892, accuracy=0.9145, size=4256314 bytes
```

### What Gets Sent

Each update contains:
- **Weights**: LSTM model parameters (embedding, LSTM, dense layers)
- **Metrics**: Local loss, accuracy
- **Metadata**: Client ID, timestamp

Size: ~4-5 MB per client (serialized neural network weights)

### Aggregation Process

```python
# Server-side federated averaging:
aggregated = (client_1_weights + client_2_weights) / 2
# Sets global model to average
# Next round, clients fetch this averaged model
```

---

## Triggering Training Cycles

### Method 1: Automated (Recommended for Testing)

```bash
python control.py --mode train --rounds 5 --wait 15
```

- Waits 15s for clients to train and submit
- Automatically triggers aggregation
- Repeats 5 times
- Best for demos and testing

### Method 2: Manual Control

```bash
# Terminal 1: Check what's pending
python control.py --mode status

# Terminal 2: When ready to aggregate
python control.py --mode trigger

# Repeat
```

### Method 3: API Calls

```bash
# Trigger aggregation directly
curl -X POST http://localhost:5000/trigger_round

# Get current status
curl http://localhost:5000/status | jq

# Get metrics
curl http://localhost:5000/metrics
```
