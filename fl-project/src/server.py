import os
import json
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify
from datetime import datetime
from prometheus_client import Counter, Histogram, generate_latest
import logging
import sys
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Import structured logger
try:
    from utils.structured_logger import logger as structured_logger
except ImportError:
    class MockLogger:
        def log(self, *args, **kwargs): pass
        def log_attack_detected(self, *args, **kwargs): pass
        def log_attack_rejected(self, *args, **kwargs): pass
        def log_round_start(self, *args, **kwargs): pass
        def log_round_end(self, *args, **kwargs): pass
        def log_error(self, *args, **kwargs): pass
    structured_logger = MockLogger()

# Import security detectors
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'audit'))
try:
    from audit.detect_poisoning import PoisoningDetector
    from audit.detect_sybil_attacks import SybilDetector
    print(" Security detectors loaded successfully")
except ImportError as e:
    print(f" Warning: Security detectors not available: {e}")
    PoisoningDetector = None
    SybilDetector = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FL-Server")

app = Flask(__name__)

# Prometheus Metrics
updates_received = Counter('fl_updates_received', 'Number of model updates received', ['client_id'])
updates_rejected = Counter('fl_updates_rejected', 'Number of rejected updates', ['client_id', 'reason'])
training_round = Counter('fl_training_round', 'Training round number')
attack_detected = Counter('fl_attack_detected', 'Security attacks detected', ['type', 'client_id'])

class FLServer:
    def __init__(self):
        self.round = 0
        self.global_model = self._create_model()
        self.client_updates = {}
        self.client_states = {}
        self.rejected_updates = []
        self.training_history = []

        # Security: Token & Keys
        self.registration_token = os.getenv('REGISTRATION_TOKEN', 'default_insecure_token')
        self.client_keys = {}
        self.server_private_key = ed25519.Ed25519PrivateKey.generate()
        self.server_public_key = self.server_private_key.public_key()

        # Detectors
        self.poisoning_detector = PoisoningDetector() if PoisoningDetector else None
        self.sybil_detector = SybilDetector() if SybilDetector else None

        structured_logger.log(event_type="SERVER_START", message="FL Server Initialized (Secure Mode)")
        logger.info("FL Server initialized with cryptographic security")

    def _create_model(self):
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(10000, 100, input_length=3),
            tf.keras.layers.LSTM(150),
            tf.keras.layers.Dense(10000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        model.build(input_shape=(None, 3))
        return model

    def register_client(self, client_id, meta_data, token, public_key_pem):
        """Register a client securely with token and public key"""
        # Verify registration token
        if token != self.registration_token:
            logger.warning(f" Unauthorized registration attempt from {client_id}")
            return {'status': 'rejected', 'reason': 'Invalid Registration Token'}, 403

        # Store client's public key
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            self.client_keys[client_id] = public_key
        except Exception as e:
            logger.error(f"Invalid public key from {client_id}: {e}")
            return {'status': 'rejected', 'reason': 'Invalid Public Key Format'}, 400

        # Initialize client state
        if client_id not in self.client_states:
            self.client_states[client_id] = {
                'joined_at': datetime.now().isoformat(),
                'updates_accepted': 0,
                'updates_rejected': 0,
                'suspicious_count': 0
            }
            logger.info(f" Client {client_id} successfully registered with secure key")

        # Send server's public key and initial model weights
        server_pub_pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        initial_weights = [w.tolist() for w in self.global_model.get_weights()]

        return {
            'status': 'registered',
            'round': self.round,
            'client_id': client_id,
            'server_public_key': server_pub_pem,
            'initial_weights': initial_weights
        }, 200

    def verify_signature(self, client_id, payload_bytes, signature_b64):
        """Verify the digital signature of an update"""
        if client_id not in self.client_keys:
            logger.error(f" Unknown client {client_id} attempted update")
            return False
        
        try:
            public_key = self.client_keys[client_id]
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, payload_bytes)
            logger.info(f" Signature verified for {client_id}")
            return True
        except Exception as e:
            logger.error(f" Signature verification failed for {client_id}: {e}")
            return False

    def process_update(self, client_id, weights, metrics):
        """Process update with Security Analysis"""
        logger.info(f"Processing update from {client_id}")
        updates_received.labels(client_id=client_id).inc()

        is_malicious = False
        rejection_reason = None
        confidence = 0.0

        # Poisoning Detection
        if self.poisoning_detector:
            global_weights = self.global_model.get_weights()
            analysis = self.poisoning_detector.analyze_update(client_id, weights, global_weights)

            if analysis['is_poisoned']:
                is_malicious = True
                rejection_reason = "POISONING_DETECTED"
                confidence = analysis.get('confidence', 0.95)
                logger.warning(f" POISONING DETECTED from {client_id} (Conf: {confidence:.2f})")

                structured_logger.log_attack_detected(
                    attack_type="POISONING", client_id=client_id,
                    confidence=confidence, details=analysis
                )
                attack_detected.labels(type='poisoning', client_id=client_id).inc()

        # Sybil Detection
        if self.sybil_detector and not is_malicious:
            # Check for sybil patterns across recent updates
            sybil_analysis = self.sybil_detector.analyze_updates(
                self.client_updates, 
                client_id, 
                weights
            )
            
            if sybil_analysis.get('is_sybil', False):
                is_malicious = True
                rejection_reason = "SYBIL_ATTACK_DETECTED"
                confidence = sybil_analysis.get('confidence', 0.90)
                logger.warning(f" SYBIL ATTACK DETECTED involving {client_id} (Conf: {confidence:.2f})")
                
                structured_logger.log_attack_detected(
                    attack_type="SYBIL", client_id=client_id,
                    confidence=confidence, details=sybil_analysis
                )
                attack_detected.labels(type='sybil', client_id=client_id).inc()

        if is_malicious:
            self.rejected_updates.append({
                'client_id': client_id, 
                'reason': rejection_reason, 
                'round': self.round,
                'timestamp': datetime.now().isoformat(),
                'confidence': confidence
            })
            
            self.client_states[client_id]['updates_rejected'] += 1
            self.client_states[client_id]['suspicious_count'] += 1
            
            structured_logger.log_attack_rejected(
                attack_type=rejection_reason, 
                client_id=client_id, 
                confidence=confidence
            )
            updates_rejected.labels(client_id=client_id, reason=rejection_reason).inc()
            return False, rejection_reason

        # Accept update
        self.client_updates[client_id] = {'weights': weights, 'metrics': metrics}
        self.client_states[client_id]['updates_accepted'] += 1
        logger.info(f" Update accepted from {client_id}")
        return True, "ACCEPTED"

    def aggregate_model(self):
        """Aggregate client updates into global model"""
        if not self.client_updates:
            logger.warning("No updates to aggregate")
            return False

        logger.info(f"Aggregating {len(self.client_updates)} updates...")
        new_weights = [np.zeros_like(w) for w in self.global_model.get_weights()]
        count = len(self.client_updates)

        # Simple average aggregation
        for data in self.client_updates.values():
            for i, w in enumerate(data['weights']):
                new_weights[i] += w

        new_weights = [w / count for w in new_weights]
        self.global_model.set_weights(new_weights)

        # Record training history
        self.training_history.append({
            'round': self.round,
            'num_clients': count,
            'timestamp': datetime.now().isoformat()
        })

        structured_logger.log_round_end(
            round_number=self.round, 
            success=True, 
            num_clients=count
        )
        
        logger.info(f" Model aggregated successfully (round {self.round})")
        
        self.client_updates.clear()
        self.round += 1
        training_round.inc()
        return True

server = FLServer()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy', 
        'round': server.round,
        'clients': len(server.client_states),
        'pending_updates': len(server.client_updates)
    })

@app.route('/init_client', methods=['POST'])
def init_client():
    """Register a new client with token and public key"""
    data = request.json
    response, status_code = server.register_client(
        data.get('client_id'), 
        data, 
        data.get('token'), 
        data.get('public_key')
    )
    return jsonify(response), status_code

@app.route('/get_model', methods=['POST'])
def get_model():
    """Send SIGNED global model to client"""
    try:
        weights = [w.tolist() for w in server.global_model.get_weights()]
        payload_content = {
            'weights': weights, 
            'round': server.round
        }

        # Sign the payload
        payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
        signature = server.server_private_key.sign(payload_bytes)
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        return jsonify({
            'payload': payload_content, 
            'signature': signature_b64
        })
    except Exception as e:
        logger.error(f"Error sending model: {e}")
        structured_logger.log_error("Model distribution failed", error=str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/submit_update', methods=['POST'])
def submit_update():
    """Receive SIGNED update from client"""
    try:
        data_json = request.json
        payload_content = data_json.get('payload')
        signature = data_json.get('signature')
        client_id = payload_content.get('client_id')

        # Verify signature
        payload_bytes = json.dumps(payload_content, sort_keys=True).encode()

        if not server.verify_signature(client_id, payload_bytes, signature):
            structured_logger.log_error(
                "Invalid Signature", 
                client_id=client_id
            )
            return jsonify({
                'status': 'rejected', 
                'reason': 'Invalid Signature'
            }), 401

        # Extract update data
        weights = [np.array(w) for w in payload_content.get('weights')]
        metrics = payload_content.get('metrics')

        # Process update with security checks
        accepted, reason = server.process_update(client_id, weights, metrics)
        
        return jsonify({
            'status': 'accepted' if accepted else 'rejected', 
            'reason': reason
        }), 200 if accepted else 403

    except Exception as e:
        logger.error(f"Error processing update: {e}")
        structured_logger.log_error("Update processing failed", error=str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/trigger_round', methods=['POST'])
def trigger_round():
    """Trigger model aggregation"""
    structured_logger.log_round_start(server.round)
    success = server.aggregate_model()
    return jsonify({
        'status': 'aggregated' if success else 'skipped', 
        'round': server.round,
        'message': 'Model aggregated successfully' if success else 'No updates to aggregate'
    })

@app.route('/wait_for_round', methods=['POST'])
def wait_for_round():
    """Endpoint for clients to wait for training signal"""
    # Simple implementation - always return ready
    # In production, this could implement sophisticated signaling
    return jsonify({'status': 'ready', 'round': server.round}), 200

@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint"""
    from prometheus_client import REGISTRY
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/status', methods=['GET'])
def status():
    """Detailed server status"""
    return jsonify({
        'round': server.round, 
        'clients': server.client_states,
        'pending_updates': list(server.client_updates.keys()),
        'rejected_updates_count': len(server.rejected_updates),
        'total_clients': len(server.client_states),
        'security': {
            'poisoning_detector': 'enabled' if server.poisoning_detector else 'disabled',
            'sybil_detector': 'enabled' if server.sybil_detector else 'disabled'
        }
    })

@app.route('/security/status', methods=['GET'])
def security_status():
    """Security monitoring status"""
    return jsonify({
        'security_monitoring': 'ACTIVE',
        'total_attacks_prevented': len(server.rejected_updates),
        'recent_attacks': server.rejected_updates[-10:] if server.rejected_updates else [],
        'detectors': {
            'poisoning': 'enabled' if server.poisoning_detector else 'disabled',
            'sybil': 'enabled' if server.sybil_detector else 'disabled'
        }
    })

@app.route('/security/rejected', methods=['GET'])
def rejected_updates():
    """Get list of rejected updates"""
    return jsonify({
        'count': len(server.rejected_updates),
        'updates': server.rejected_updates
    })

if __name__ == '__main__':
    logger.info("Starting FL Server on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)