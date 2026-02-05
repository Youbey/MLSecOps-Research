import os
import json
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import sys
import threading
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SERVER")

app = Flask(__name__)

class FLServer:
    def __init__(self):
        self.round = 0
        self.max_rounds = int(os.getenv('FL_ROUNDS', 10))
        self.global_model = self._load_or_create_model()
        
        # State management
        self.client_states = {}
        self.client_updates = {}
        self.waiting_clients = defaultdict(threading.Event)
        self.round_in_progress = False
        self.round_lock = threading.Lock()
        
        # Audit log
        self.audit_log = []
        self.detected_attacks = []
        
        logger.info(f"Server initialized for {self.max_rounds} rounds")
    
    def _load_or_create_model(self):
        """Load pre-trained model from file, or create new one if not found"""
        model_path = os.getenv('SERVER_MODEL_PATH', './data/global_model.h5')
        
        # Try to load pre-trained model
        if os.path.exists(model_path):
            try:
                logger.info(f"Loading pre-trained model from {model_path}")
                model = tf.keras.models.load_model(model_path)
                logger.info(f"Successfully loaded pre-trained model from {model_path}")
                return model
            except Exception as e:
                logger.warning(f"Failed to load model from {model_path}: {e}")
                logger.info("Creating new model instead")
        else:
            logger.info(f"Model file not found at {model_path}")
            logger.info("Creating new model from scratch")
        
        # Fall back to creating new model
        return self._create_model()
    
    def _create_model(self):
        """Create a new global model (same architecture as clients)"""
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(10000, 100, input_length=3),
            tf.keras.layers.LSTM(150),
            tf.keras.layers.Dense(10000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        model.build(input_shape=(None, 3))
        logger.info("Created new model: Embedding(10000, 100) → LSTM(150) → Dense(10000)")
        return model
    
    def register_client(self, client_id, num_samples):
        if client_id not in self.client_states:
            self.client_states[client_id] = {
                'registered_at': datetime.now().isoformat(),
                'updates_received': 0,
                'updates_accepted': 0,
                'updates_rejected': 0,
                'num_samples': num_samples,
                'last_metrics': None,
                'attacks_detected': []
            }
            logger.info(f"Client registered: {client_id} ({num_samples} samples)")
            self._log_audit('CLIENT_REGISTERED', {'client_id': client_id, 'num_samples': num_samples})
        
        # SEND INITIAL MODEL WEIGHTS TO CLIENT
        weights = [w.tolist() for w in self.global_model.get_weights()]
        logger.info(f"Sending initial model weights to {client_id} (round {self.round})")
        
        return {
            'status': 'initialized',
            'round': self.round,
            'client_id': client_id,
            'initial_weights': weights
        }
    
    def detect_poisoning(self, client_id, weights, global_weights):
        """Detect poisoning attacks using statistical analysis"""
        try:
            # Flatten weights for analysis
            client_flat = np.concatenate([w.flatten() for w in weights])
            global_flat = np.concatenate([w.flatten() for w in global_weights])
            
            # Calculate L2 norm of update
            l2_norm = np.linalg.norm(client_flat - global_flat)
            
            # Calculate statistics
            mean_val = np.mean(np.abs(client_flat))
            std_val = np.std(np.abs(client_flat))
            
            # Anomaly detection: if norm is suspiciously large
            threshold = np.linalg.norm(global_flat) * 2.0
            
            if l2_norm > threshold:
                confidence = min(0.95, (l2_norm / threshold) * 0.9)
                return True, confidence, {
                    'l2_norm': float(l2_norm),
                    'threshold': float(threshold),
                    'mean': float(mean_val),
                    'std': float(std_val)
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in poisoning detection: {e}")
            return False, 0.0, {}
    
    def process_update(self, client_id, weights, metrics):
        """Process and analyze client update"""
        logger.info(f"Processing update from {client_id} (Round {self.round})")
        
        self.client_states[client_id]['updates_received'] += 1
        self.client_states[client_id]['last_metrics'] = metrics
        
        # Security analysis
        global_weights = self.global_model.get_weights()
        is_poisoned, confidence, detection_details = self.detect_poisoning(client_id, weights, global_weights)
        
        # Log the analysis
        analysis = {
            'round': self.round,
            'client_id': client_id,
            'timestamp': datetime.now().isoformat(),
            'is_poisoned': is_poisoned,
            'confidence': float(confidence),
            'detection_details': detection_details,
            'metrics': metrics
        }
        self._log_audit('UPDATE_ANALYZED', analysis)
        
        if is_poisoned:
            logger.warning(f"ATTACK DETECTED: {client_id} in round {self.round} (confidence={confidence:.2f})")
            self.detected_attacks.append(analysis)
            self.client_states[client_id]['attacks_detected'].append({
                'round': self.round,
                'confidence': confidence,
                'details': detection_details
            })
            self.client_states[client_id]['updates_rejected'] += 1
            return False, "POISONING_DETECTED"
        
        # Store valid update
        self.client_updates[client_id] = {
            'weights': weights,
            'metrics': metrics,
            'timestamp': datetime.now()
        }
        self.client_states[client_id]['updates_accepted'] += 1
        logger.info(f"Update accepted from {client_id}")
        return True, "ACCEPTED"
    
    def aggregate_model(self):
        """Aggregate accepted updates using FedAvg"""
        if not self.client_updates:
            logger.warning("No updates to aggregate")
            return False
        
        logger.info(f"Starting aggregation with {len(self.client_updates)} clients")
        
        new_weights = [np.zeros_like(w) for w in self.global_model.get_weights()]
        total_samples = 0
        
        for client_id, data in self.client_updates.items():
            client_weights = data['weights']
            num_samples = self.client_states[client_id]['num_samples']
            
            for i, w in enumerate(client_weights):
                new_weights[i] += np.array(w) * num_samples
            total_samples += num_samples
        
        # Average
        new_weights = [w / total_samples for w in new_weights]
        self.global_model.set_weights(new_weights)
        
        logger.info(f"Aggregation completed - Round {self.round} finished")
        self._log_audit('AGGREGATION_COMPLETED', {
            'round': self.round,
            'num_updates': len(self.client_updates),
            'num_attacks_detected': len([a for a in self.detected_attacks if a['round'] == self.round])
        })
        
        # Clear for next round
        self.client_updates.clear()
        self.round += 1
        
        return True
    
    def signal_clients_for_round(self):
        """Signal all clients to begin training"""
        for client_id in self.client_states:
            self.waiting_clients[client_id].set()
        logger.info(f"Signaled all clients to begin round {self.round}")
        self._log_audit('ROUND_STARTED', {'round': self.round, 'num_clients': len(self.client_states)})
    
    def reset_client_signals(self):
        """Reset all client signals for next round"""
        for client_id in self.client_states:
            self.waiting_clients[client_id].clear()
    
    def _log_audit(self, event_type, data):
        """Log event to audit trail"""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'data': data
        }
        self.audit_log.append(audit_entry)
    
    def save_round_report(self):
        """Save detailed report of current round"""
        report = {
            'round': self.round - 1,  # Previous round (now completed)
            'timestamp': datetime.now().isoformat(),
            'clients': dict(self.client_states),
            'attacks_detected': self.detected_attacks,
            'total_updates_received': sum(c['updates_received'] for c in self.client_states.values()),
            'total_updates_accepted': sum(c['updates_accepted'] for c in self.client_states.values()),
            'total_updates_rejected': sum(c['updates_rejected'] for c in self.client_states.values()),
            'audit_log': self.audit_log
        }
        
        filename = f'/tmp/round_{self.round - 1:02d}_report.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Round report saved to {filename}")
        return filename

# Initialize server
server = FLServer()

# ==============================================================================
# FLASK ROUTES
# ==============================================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'round': server.round,
        'clients': len(server.client_states)
    })

@app.route('/init_client', methods=['POST'])
def init_client():
    data = request.json
    client_id = data.get('client_id')
    num_samples = data.get('num_samples', 0)
    
    response = server.register_client(client_id, num_samples)
    return jsonify(response)

@app.route('/get_model', methods=['POST'])
def get_model():
    """Send global model weights to client"""
    try:
        weights = [w.tolist() for w in server.global_model.get_weights()]
        return jsonify({
            'weights': weights,
            'round': server.round
        })
    except Exception as e:
        logger.error(f"Error sending model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/submit_update', methods=['POST'])
def submit_update():
    """Receive model update from client"""
    try:
        data = request.json
        client_id = data.get('client_id')
        weights = [np.array(w) for w in data.get('weights', [])]
        metrics = data.get('metrics', {})
        
        logger.info(f"Update received from {client_id} ({len(weights)} layers)")
        
        accepted, reason = server.process_update(client_id, weights, metrics)
        
        if accepted:
            return jsonify({'status': 'accepted', 'round': server.round})
        else:
            return jsonify({'status': 'rejected', 'reason': reason}), 403
    
    except Exception as e:
        logger.error(f"Error processing update: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/wait_for_round', methods=['POST'])
def wait_for_round():
    """Client waits here until server signals training round"""
    data = request.json
    client_id = data.get('client_id')
    
    # Get or create event for this client
    event = server.waiting_clients[client_id]
    
    # Wait for signal (with timeout)
    signaled = event.wait(timeout=300)
    
    if signaled:
        # Reset the event for next round
        event.clear()
        return jsonify({'status': 'go_train', 'round': server.round})
    else:
        return jsonify({'status': 'timeout'}), 408

@app.route('/trigger_round', methods=['POST'])
def trigger_round():
    """Trigger a training round - signal all waiting clients"""
    logger.info(f"Triggering training round {server.round}")
    server.signal_clients_for_round()
    return jsonify({'status': 'triggered', 'round': server.round}), 200

@app.route('/status', methods=['GET'])
def status():
    """Get detailed server status"""
    return jsonify({
        'round': server.round,
        'clients': dict(server.client_states),
        'pending_updates': list(server.client_updates.keys()),
        'attacks_detected_this_round': len([a for a in server.detected_attacks if a['round'] == server.round]),
        'total_attacks_detected': len(server.detected_attacks)
    })

@app.route('/security/status', methods=['GET'])
def security_status():
    """Security dashboard"""
    return jsonify({
        'monitoring': 'ACTIVE',
        'total_attacks_detected': len(server.detected_attacks),
        'attacks': server.detected_attacks
    })

if __name__ == '__main__':
    logger.info("Starting FL Server")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)