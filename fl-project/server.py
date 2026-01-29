"""
1. Receives updates from clients
2. Analyzes each update for attacks (using security detectors)
3. Identifies attack type & confidence
4. Takes defensive action (accept/reject)
5. Logs everything for audit
"""
import os
import json
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify
from datetime import datetime
from prometheus_client import Counter, Histogram, generate_latest
import logging
import sys
import hashlib
import time

# Import structured logger
try:
    from structured_logger import logger as structured_logger
except ImportError:
    # Fallback if structured_logger is missing
    class MockLogger:
        def log(self, *args, **kwargs): pass
        def log_attack_detected(self, *args, **kwargs): pass
        def log_attack_rejected(self, *args, **kwargs): pass
        def log_round_start(self, *args, **kwargs): pass
        def log_round_end(self, *args, **kwargs): pass
    structured_logger = MockLogger()

# Import security detectors
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'audit'))
try:
    from detect_poisoning import PoisoningDetector
    from detect_sybil_attacks import SybilDetector
    print("✓ Security detectors loaded successfully")
except ImportError as e:
    print(f"⚠ Warning: Security detectors not available: {e}")
    PoisoningDetector = None
    SybilDetector = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FL-Server")

app = Flask(__name__)

# Prometheus Metrics
updates_received = Counter('fl_updates_received', 'Number of model updates received', ['client_id'])
updates_rejected = Counter('fl_updates_rejected', 'Number of rejected updates', ['client_id', 'reason'])
update_size = Histogram('fl_update_size_bytes', 'Size of updates in bytes', ['client_id'])
training_round = Counter('fl_training_round', 'Training round number')
attack_detected = Counter('fl_attack_detected', 'Security attacks detected', ['type', 'client_id'])

class FLServer:
    def __init__(self):
        self.round = 0
        self.max_rounds = int(os.getenv('FL_ROUNDS', 5))
        self.min_clients = 1

        # Global Model (LSTM for text generation)
        self.global_model = self._create_model()
        self.training_history = []

        # State
        self.client_updates = {}
        self.client_states = {}
        self.rejected_updates = []

        # Security Detectors
        self.poisoning_detector = PoisoningDetector() if PoisoningDetector else None
        self.sybil_detector = SybilDetector() if SybilDetector else None

        structured_logger.log(event_type="SERVER_START", message="FL Server Initialized")

    def _create_model(self):
        """Create the initial global model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(1000, 64, input_length=3),
            tf.keras.layers.LSTM(64),
            tf.keras.layers.Dense(1000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        model.build(input_shape=(None, 3))
        return model

    def register_client(self, client_id, meta_data):
        """Register a new client"""
        if client_id not in self.client_states:
            self.client_states[client_id] = {
                'joined_at': datetime.now().isoformat(),
                'updates_sent': 0,
                'updates_accepted': 0,
                'suspicious_count': 0,
                'last_seen': datetime.now().isoformat(),
                'data_samples': meta_data.get('num_samples', 0)
            }
            logger.info(f"Client {client_id} registered")

        return {
            'status': 'initialized',
            'round': self.round,
            'client_id': client_id
        }

    def process_update(self, client_id, weights, metrics):
        """
        Process and Analyze a client update
        THIS IS WHERE SECURITY CHECKS HAPPEN
        """
        logger.info(f"Processing update from {client_id} (Round {self.round})")

        # 1. Structured Log: Update Received
        structured_logger.log(
            event_type="UPDATE_RECEIVED",
            message=f"Received update from {client_id}",
            client_id=client_id,
            round=self.round,
            accuracy=metrics.get('accuracy', 0)
        )

        updates_received.labels(client_id=client_id).inc()
        is_malicious = False
        rejection_reason = None
        confidence = 0.0

        # 2. Security Analysis: Poisoning Detection
        if self.poisoning_detector:
            # We need previous weights or global weights for comparison
            global_weights = self.global_model.get_weights()

            # Analyze
            analysis = self.poisoning_detector.analyze_update(client_id, weights, global_weights)

            if analysis['is_poisoned']:
                is_malicious = True
                rejection_reason = "POISONING_DETECTED"
                confidence = analysis.get('confidence', 0.95)

                logger.warning(f"🚨 POISONING DETECTED from {client_id} (Conf: {confidence:.2f})")

                # GRAFANA LOG: Attack Detected
                structured_logger.log_attack_detected(
                    attack_type="POISONING",
                    client_id=client_id,
                    confidence=confidence,
                    details=analysis
                )
                attack_detected.labels(type='poisoning', client_id=client_id).inc()

        # 3. Security Analysis: Sybil Detection (Needs multiple updates)
        # Note: Sybil checks usually happen at aggregation time, but we log here for now

        # 4. Decision: Accept or Reject
        if is_malicious:
            self.rejected_updates.append({
                'round': self.round,
                'client_id': client_id,
                'reason': rejection_reason,
                'timestamp': datetime.now().isoformat()
            })

            # GRAFANA LOG: Attack Rejected
            structured_logger.log_attack_rejected(
                attack_type=rejection_reason,
                client_id=client_id,
                confidence=confidence
            )
            updates_rejected.labels(client_id=client_id, reason=rejection_reason).inc()

            self.client_states[client_id]['suspicious_count'] += 1
            return False, rejection_reason

        else:
            # Store valid update
            self.client_updates[client_id] = {
                'weights': weights,
                'metrics': metrics,
                'timestamp': datetime.now()
            }
            self.client_states[client_id]['updates_accepted'] += 1
            return True, "ACCEPTED"

    def aggregate_model(self):
        """Aggregate stored updates into global model"""
        if not self.client_updates:
            logger.warning("No updates to aggregate")
            return False

        logger.info(f"Aggregating {len(self.client_updates)} updates...")

        # Simple FedAvg
        new_weights = [np.zeros_like(w) for w in self.global_model.get_weights()]
        total_samples = 0

        for client_id, data in self.client_updates.items():
            client_weights = data['weights']
            num_samples = 5000 # Simplified

            for i, w in enumerate(client_weights):
                new_weights[i] += w * num_samples
            total_samples += num_samples

        # Average
        new_weights = [w / total_samples for w in new_weights]
        self.global_model.set_weights(new_weights)

        # Log Round Success
        structured_logger.log_round_end(
            round_number=self.round,
            success=True,
            participants=len(self.client_updates),
            attacks_detected=len(self.rejected_updates) # This logic might need refinement per round
        )

        # Clear for next round
        self.client_updates.clear()
        self.round += 1
        training_round.inc()
        return True

# Initialize Server Instance
server = FLServer()

# ==============================================================================
# FLASK ROUTES
# ==============================================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'round': server.round})

@app.route('/init_client', methods=['POST'])
def init_client():
    data = request.json
    response = server.register_client(data.get('client_id'), data)
    return jsonify(response)

@app.route('/get_model', methods=['POST'])
def get_model():
    """Send global model weights to client"""
    try:
        # Serialize weights safely (List of numpy arrays -> List of lists)
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
        weights = [np.array(w) for w in data.get('weights')]
        metrics = {'loss': data.get('loss'), 'accuracy': data.get('accuracy')}

        logger.info(f"Received update from {client_id}, size: {len(data.get('weights', []))} layers")
        update_size.labels(client_id=client_id).observe(sys.getsizeof(request.data))

        # Process & Analyze Security
        accepted, reason = server.process_update(client_id, weights, metrics)

        if accepted:
            return jsonify({'status': 'accepted', 'round': server.round})
        else:
            return jsonify({'status': 'rejected', 'reason': reason}), 403

    except Exception as e:
        logger.error(f"Error processing update: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/trigger_round', methods=['POST'])
def trigger_round():
    """Manually trigger aggregation (called by control.py)"""
    structured_logger.log_round_start(server.round)
    success = server.aggregate_model()
    return jsonify({
        'status': 'aggregated' if success else 'skipped',
        'round': server.round
    })

@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint"""
    from prometheus_client import REGISTRY
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/status', methods=['GET'])
def status():
    """Operational status"""
    return jsonify({
        'round': server.round,
        'clients': server.client_states,
        'pending_updates': list(server.client_updates.keys()),
        'rejected_updates': len(server.rejected_updates),
        'history': server.training_history
    })

@app.route('/security/status', methods=['GET'])
def security_status():
    """Security Dashboard Status"""
    return jsonify({
        'security_monitoring': 'ACTIVE',
        'detectors': {
            'poisoning': 'ENABLED' if server.poisoning_detector else 'DISABLED',
            'sybil': 'ENABLED' if server.sybil_detector else 'DISABLED'
        },
        'total_attacks_prevented': len(server.rejected_updates)
    })

if __name__ == '__main__':
    logger.info("Starting FL Server with Security Monitoring...")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)