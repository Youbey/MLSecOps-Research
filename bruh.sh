# Create project directory
mkdir -p fl-project
cd fl-project

# Create requirements.txt
cat > requirements.txt << 'EOF'
flask==2.3.0
flask-cors==4.0.0
tensorflow==2.13.0
numpy==1.24.3
requests==2.31.0
python-dotenv==1.0.0
prometheus-client==0.17.1
cryptography==41.0.0
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
# Use Python 3.10 slim image
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Default to server
CMD ["python", "server.py"]
EOF

# Create server.py
cat > server.py << 'EOF'
import os
import json
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify
from datetime import datetime
from prometheus_client import Counter, Histogram, generate_latest
import logging
from functools import wraps
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FL-Server")

app = Flask(__name__)

# Metrics for monitoring
updates_received = Counter('fl_updates_received', 'Number of model updates received', ['client_id'])
update_size = Histogram('fl_update_size_bytes', 'Size of updates in bytes', ['client_id'])
training_round = Counter('fl_training_round', 'Training round number')

class FLServer:
    def __init__(self):
        self.global_model = self._create_model()
        self.client_updates = {}
        self.round = 0
        self.training_history = []
        self.client_states = {}  # Track client metadata
        
    def _create_model(self):
        """Create word prediction model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(1000, 32, input_length=3),
            tf.keras.layers.LSTM(64, return_sequences=False),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(1000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        return model
    
    def aggregate_updates(self, updates, num_clients):
        """Federated averaging"""
        aggregated_weights = None
        
        for client_id, weights in updates.items():
            weights = np.array(weights)
            if aggregated_weights is None:
                aggregated_weights = weights.copy()
            else:
                aggregated_weights += weights
        
        aggregated_weights /= len(updates)
        logger.info(f"Aggregated {len(updates)} client updates")
        return aggregated_weights.tolist()
    
    def get_model_weights(self):
        return [w.tolist() for w in self.global_model.get_weights()]
    
    def set_model_weights(self, weights):
        weights = [np.array(w) for w in weights]
        self.global_model.set_weights(weights)
    
    def save_state(self):
        """Persist model and metadata"""
        state = {
            'round': self.round,
            'weights': self.get_model_weights(),
            'history': self.training_history,
            'client_states': self.client_states,
            'timestamp': datetime.now().isoformat()
        }
        with open('server_state.json', 'w') as f:
            json.dump(state, f)
        logger.info(f"Server state saved at round {self.round}")

server = FLServer()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'round': server.round})

@app.route('/init_client', methods=['POST'])
def init_client():
    """Initialize client"""
    data = request.json
    client_id = data.get('client_id')
    
    server.client_states[client_id] = {
        'first_seen': datetime.now().isoformat(),
        'updates_sent': 0,
        'last_update': None,
        'data_samples': data.get('num_samples', 0)
    }
    
    logger.info(f"Client {client_id} initialized with {data.get('num_samples', 0)} samples")
    return jsonify({
        'status': 'initialized',
        'client_id': client_id,
        'round': server.round
    })

@app.route('/get_model', methods=['POST'])
def get_model():
    """Send current model to client"""
    data = request.json
    client_id = data.get('client_id')
    
    weights = server.get_model_weights()
    response = {
        'weights': weights,
        'round': server.round,
        'model_hash': hashlib.md5(str(weights[:1]).encode()).hexdigest()[:8]
    }
    
    logger.info(f"Model sent to {client_id} at round {server.round}")
    return jsonify(response)

@app.route('/submit_update', methods=['POST'])
def submit_update():
    """Receive local model update from client"""
    data = request.json
    client_id = data.get('client_id')
    weights = data.get('weights')
    metrics = data.get('metrics', {})
    
    # Log update details
    size_bytes = len(json.dumps(weights))
    updates_received.labels(client_id=client_id).inc()
    update_size.labels(client_id=client_id).observe(size_bytes)
    
    # Update client state
    server.client_states[client_id]['updates_sent'] += 1
    server.client_states[client_id]['last_update'] = datetime.now().isoformat()
    server.client_states[client_id]['last_metrics'] = metrics
    
    server.client_updates[client_id] = {
        'weights': weights,
        'metrics': metrics,
        'timestamp': datetime.now().isoformat()
    }
    
    logger.info(f"Update from {client_id}: loss={metrics.get('loss', 'N/A')}, "
                f"accuracy={metrics.get('accuracy', 'N/A')}, size={size_bytes} bytes")
    
    return jsonify({'status': 'received', 'update_id': f"{server.round}_{client_id}"})

@app.route('/trigger_round', methods=['POST'])
def trigger_round():
    """Trigger federated learning round"""
    if len(server.client_updates) == 0:
        return jsonify({'error': 'No client updates available'}), 400
    
    logger.info(f"Starting federated round {server.round + 1}")
    
    # Aggregate weights
    aggregated = server.aggregate_updates(
        {cid: update['weights'] for cid, update in server.client_updates.items()},
        num_clients=len(server.client_updates)
    )
    
    # Update global model
    server.set_model_weights(aggregated)
    
    # Record history
    history_entry = {
        'round': server.round,
        'num_clients': len(server.client_updates),
        'timestamp': datetime.now().isoformat(),
        'client_metrics': {cid: update['metrics'] 
                          for cid, update in server.client_updates.items()}
    }
    server.training_history.append(history_entry)
    
    server.round += 1
    server.client_updates = {}
    
    # Save state
    server.save_state()
    training_round.inc()
    
    logger.info(f"Round {server.round - 1} completed and saved")
    return jsonify({
        'status': 'aggregated',
        'round': server.round - 1,
        'clients_aggregated': len(history_entry['num_clients'])
    })

@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest()

@app.route('/status', methods=['GET'])
def status():
    """Get server status and monitoring info"""
    return jsonify({
        'round': server.round,
        'total_updates': sum(s['updates_sent'] for s in server.client_states.values()),
        'clients': server.client_states,
        'pending_updates': list(server.client_updates.keys()),
        'history': server.training_history[-5:]  # Last 5 rounds
    })

if __name__ == '__main__':
    logger.info("Starting FL Server on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

# Create client.py
cat > client.py << 'EOF'
import os
import sys
import json
import numpy as np
import tensorflow as tf
import requests
import time
import logging
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"FL-Client")

class FLClient:
    def __init__(self, client_id, server_url, data_file):
        self.client_id = client_id
        self.server_url = server_url
        self.model = self._create_model()
        self.training_data = self._load_data(data_file)
        self.round = 0
        self.update_history = []
        
        logger.info(f"Client {client_id} initialized")
        self._register_with_server()
    
    def _create_model(self):
        """Create word prediction model (same as server)"""
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(1000, 32, input_length=3),
            tf.keras.layers.LSTM(64, return_sequences=False),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(1000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        return model
    
    def _load_data(self, data_file):
        """Load training data from file"""
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        X = np.array(data['X'])
        y = np.array(data['y'])
        logger.info(f"Loaded {len(X)} training samples")
        return X, y
    
    def _register_with_server(self):
        """Register client with server"""
        try:
            response = requests.post(
                f'{self.server_url}/init_client',
                json={
                    'client_id': self.client_id,
                    'num_samples': len(self.training_data[0])
                }
            )
            logger.info(f"Registered: {response.json()}")
        except Exception as e:
            logger.error(f"Registration failed: {e}")
    
    def fetch_model(self):
        """Download global model from server"""
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            data = response.json()
            weights = [np.array(w) for w in data['weights']]
            self.model.set_weights(weights)
            self.round = data['round']
            model_hash = data.get('model_hash', 'unknown')
            logger.info(f"Fetched model from round {self.round} (hash: {model_hash})")
            return True
        except Exception as e:
            logger.error(f"Failed to fetch model: {e}")
            return False
    
    def train_locally(self, epochs=2):
        """Train model locally"""
        logger.info(f"Starting local training for {epochs} epochs")
        X, y = self.training_data
        
        history = self.model.fit(
            X, y,
            epochs=epochs,
            batch_size=8,
            verbose=0,
            validation_split=0.2
        )
        
        loss = float(history.history['loss'][-1])
        accuracy = float(history.history['accuracy'][-1])
        
        logger.info(f"Local training completed: loss={loss:.4f}, accuracy={accuracy:.4f}")
        return loss, accuracy
    
    def submit_update(self, loss, accuracy):
        """Send local model update to server"""
        try:
            weights = [w.tolist() for w in self.model.get_weights()]
            
            payload = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            size_bytes = len(json.dumps(payload))
            response = requests.post(
                f'{self.server_url}/submit_update',
                json=payload
            )
            
            logger.info(f"Update submitted: {size_bytes} bytes, "
                       f"status={response.json().get('status')}")
            return True
        except Exception as e:
            logger.error(f"Failed to submit update: {e}")
            return False
    
    def run_training_cycle(self):
        """Run one complete FL cycle: fetch -> train -> submit"""
        logger.info(f"=== Starting FL cycle ===")
        
        if not self.fetch_model():
            return False
        
        loss, accuracy = self.train_locally(epochs=2)
        
        if not self.submit_update(loss, accuracy):
            return False
        
        logger.info(f"=== FL cycle completed ===")
        return True

def main():
    client_id = os.getenv('CLIENT_ID', 'client_1')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'/data/{client_id}_data.json')
    
    logger.name = f"FL-Client-{client_id}"
    
    # Wait for server to start
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            break
        except:
            logger.info(f"Waiting for server... ({attempt + 1}/10)")
            time.sleep(2)
    
    client = FLClient(client_id, server_url, data_file)
    
    # Run continuous training cycles with intervals
    cycle = 0
    while True:
        cycle += 1
        logger.info(f"\n>>> Cycle {cycle}")
        client.run_training_cycle()
        
        # Wait before next cycle (server needs time for aggregation)
        time.sleep(5)

if __name__ == '__main__':
    main()
EOF

# Create generate_data.py
cat > generate_data.py << 'EOF'
"""
Generate synthetic word prediction data for FL clients.
Creates word sequences for autocomplete training.
"""

import json
import numpy as np
import os

def generate_client_data(client_id, num_samples=200):
    """
    Generate word prediction training data.
    Input: sequence of 3 word indices
    Output: next word index (1000 possible words)
    """
    np.random.seed(client_id)  # Different data per client
    
    X = np.random.randint(0, 1000, size=(num_samples, 3))
    y = np.random.randint(0, 1000, size=(num_samples, 1))
    
    # Add some patterns per client for diversity
    if client_id == 1:
        # Client 1: higher probability of words in range 0-300
        y = np.random.randint(0, 300, size=(num_samples, 1))
    elif client_id == 2:
        # Client 2: higher probability of words in range 300-600
        y = np.random.randint(300, 600, size=(num_samples, 1))
    
    data = {
        'X': X.tolist(),
        'y': y.tolist(),
        'num_samples': num_samples,
        'vocab_size': 1000,
        'client_id': f'client_{client_id}'
    }
    
    return data

def main():
    os.makedirs('data', exist_ok=True)
    
    for client_id in [1, 2]:
        data = generate_client_data(client_id, num_samples=200)
        filename = f'data/client_{client_id}_data.json'
        
        with open(filename, 'w') as f:
            json.dump(data, f)
        
        print(f"Generated {filename}: {data['num_samples']} samples")

if __name__ == '__main__':
    main()
EOF

# Create control.py
cat > control.py << 'EOF'
"""
Control script to:
1. Trigger training rounds
2. Monitor data flow between clients and server
3. Inspect model updates
"""

import requests
import json
import time
import sys
from datetime import datetime
import argparse

SERVER_URL = "http://localhost:5000"

class FLController:
    def __init__(self, server_url=SERVER_URL):
        self.server_url = server_url
        self.round = 0
    
    def check_server_health(self):
        """Check if server is running"""
        try:
            response = requests.get(f'{self.server_url}/health', timeout=2)
            data = response.json()
            print(f"✓ Server is healthy (round {data['round']})")
            return True
        except:
            print("✗ Server is not responding")
            return False
    
    def get_status(self):
        """Get detailed server status"""
        try:
            response = requests.get(f'{self.server_url}/status')
            data = response.json()
            
            print("\n" + "="*60)
            print(f"FEDERATION STATUS - Round {data['round']}")
            print("="*60)
            
            print(f"\nClients ({len(data['clients'])} total):")
            for client_id, state in data['clients'].items():
                print(f"  {client_id}:")
                print(f"    - Updates sent: {state['updates_sent']}")
                print(f"    - Data samples: {state['data_samples']}")
                print(f"    - Last update: {state.get('last_update', 'Never')}")
                if 'last_metrics' in state:
                    metrics = state['last_metrics']
                    print(f"    - Loss: {metrics.get('loss', 'N/A'):.4f}")
                    print(f"    - Accuracy: {metrics.get('accuracy', 'N/A'):.4f}")
            
            print(f"\nPending updates from: {data['pending_updates']}")
            
            if data['history']:
                print(f"\nRecent rounds:")
                for entry in data['history'][-3:]:
                    print(f"  Round {entry['round']}: {entry['num_clients']} clients")
                    for cid, metrics in entry['client_metrics'].items():
                        print(f"    {cid}: loss={metrics.get('loss', 'N/A'):.4f}")
            
            print("="*60 + "\n")
            return data
        except Exception as e:
            print(f"Error getting status: {e}")
            return None
    
    def trigger_round(self):
        """Trigger federated aggregation round"""
        try:
            response = requests.post(f'{self.server_url}/trigger_round')
            data = response.json()
            
            if 'error' in data:
                print(f"✗ Round failed: {data['error']}")
                return False
            
            print(f"\n✓ Aggregation round {data['round']} completed")
            print(f"  - Clients aggregated: {data['clients_aggregated']}")
            return True
        except Exception as e:
            print(f"✗ Error triggering round: {e}")
            return False
    
    def get_metrics(self):
        """Get Prometheus metrics"""
        try:
            response = requests.get(f'{self.server_url}/metrics')
            print("\n" + "="*60)
            print("PROMETHEUS METRICS")
            print("="*60)
            print(response.text)
        except Exception as e:
            print(f"Error fetching metrics: {e}")
    
    def interactive_monitor(self, interval=10):
        """Continuous monitoring mode"""
        print("Starting interactive monitoring (Ctrl+C to exit)")
        try:
            while True:
                self.get_status()
                print(f"Next update in {interval}s...\n")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped")
    
    def automated_training(self, num_rounds=5, wait_for_updates=15):
        """Automated training: wait for updates, aggregate, repeat"""
        print(f"Starting automated training for {num_rounds} rounds")
        print(f"Waiting {wait_for_updates}s for client updates each round\n")
        
        for round_num in range(1, num_rounds + 1):
            print(f"\n{'='*60}")
            print(f"ROUND {round_num}/{num_rounds}")
            print('='*60)
            
            # Wait for client updates
            print(f"Waiting {wait_for_updates}s for client updates...")
            time.sleep(wait_for_updates)
            
            # Check status
            status = self.get_status()
            if not status or not status['pending_updates']:
                print("No updates received, skipping aggregation")
                continue
            
            # Trigger aggregation
            print(f"\nTriggering aggregation for {len(status['pending_updates'])} updates...")
            self.trigger_round()
            
            time.sleep(2)
        
        print(f"\n✓ Training completed {num_rounds} rounds")
        self.get_status()

def main():
    parser = argparse.ArgumentParser(description='FL Control & Monitoring')
    parser.add_argument('--mode', default='monitor',
                       choices=['monitor', 'status', 'trigger', 'metrics', 'train'],
                       help='Operation mode')
    parser.add_argument('--rounds', type=int, default=5,
                       help='Number of rounds for automated training')
    parser.add_argument('--interval', type=int, default=10,
                       help='Monitoring interval in seconds')
    parser.add_argument('--wait', type=int, default=15,
                       help='Wait time for client updates in seconds')
    
    args = parser.parse_args()
    
    controller = FLController()
    
    if not controller.check_server_health():
        sys.exit(1)
    
    if args.mode == 'status':
        controller.get_status()
    
    elif args.mode == 'trigger':
        controller.trigger_round()
    
    elif args.mode == 'metrics':
        controller.get_metrics()
    
    elif args.mode == 'monitor':
        controller.interactive_monitor(interval=args.interval)
    
    elif args.mode == 'train':
        controller.automated_training(num_rounds=args.rounds, wait_for_updates=args.wait)

if __name__ == '__main__':
    main()
EOF

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  # FL Server
  server:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: fl_server
    environment:
      - FLASK_ENV=production
    ports:
      - "5000:5000"
      - "9090:9090"
    volumes:
      - ./server.py:/app/server.py
      - server_state:/app/state
    command: python server.py
    networks:
      - fl_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 5s
      timeout: 3s
      retries: 5

  # FL Client 1
  client_1:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: fl_client_1
    environment:
      - CLIENT_ID=client_1
      - SERVER_URL=http://server:5000
      - DATA_FILE=/data/client_1_data.json
    volumes:
      - ./client.py:/app/client.py
      - ./data:/data
      - client_1_cache:/app/cache
    depends_on:
      server:
        condition: service_healthy
    networks:
      - fl_network
    command: python client.py

  # FL Client 2
  client_2:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: fl_client_2
    environment:
      - CLIENT_ID=client_2
      - SERVER_URL=http://server:5000
      - DATA_FILE=/data/client_2_data.json
    volumes:
      - ./client.py:/app/client.py
      - ./data:/data
      - client_2_cache:/app/cache
    depends_on:
      server:
        condition: service_healthy
    networks:
      - fl_network
    command: python client.py

  # Prometheus for monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: fl_prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - fl_network

volumes:
  server_state:
  client_1_cache:
  client_2_cache:
  prometheus_data:

networks:
  fl_network:
    driver: bridge
EOF

# Create prometheus.yml
cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'fl_server'
    static_configs:
      - targets: ['server:5000']
    metrics_path: '/metrics'
EOF

# Create data directory
mkdir -p data

echo "✓ All files created successfully!"
echo ""
echo "Next steps:"
echo "1. Generate training data: python generate_data.py"
echo "2. Start containers: docker-compose up --build"
echo "3. In another terminal: python control.py --mode train --rounds 5 --wait 15"