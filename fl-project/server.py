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
        """Federated averaging - handle variable shaped layers"""
        aggregated_weights = None
        num_updates = len(updates)
        
        for client_id, weights in updates.items():
            # weights is a list of arrays (one per layer)
            if aggregated_weights is None:
                # Initialize with first client's weights
                aggregated_weights = [np.array(w, dtype=np.float32) for w in weights]
            else:
                # Add each layer from this client
                for i, w in enumerate(weights):
                    w_array = np.array(w, dtype=np.float32)
                    aggregated_weights[i] = aggregated_weights[i] + w_array
        
        # Average across all clients
        aggregated_weights = [w / num_updates for w in aggregated_weights]
        
        # Convert back to lists
        aggregated_weights = [w.tolist() for w in aggregated_weights]
        logger.info(f"Aggregated {num_updates} client updates ({len(aggregated_weights)} layers)")
        return aggregated_weights
    
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
    try:
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
        num_clients_aggregated = len(server.client_updates)
        history_entry = {
            'round': server.round,
            'num_clients': num_clients_aggregated,
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
            'clients_aggregated': num_clients_aggregated
        })
    except Exception as e:
        logger.error(f"Error in trigger_round: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint"""
    from prometheus_client import REGISTRY
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain; charset=utf-8'}

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