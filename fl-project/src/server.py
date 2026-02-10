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
        self.sybil_detector = SybilDetector(history_window=5, similarity_threshold=0.90) if SybilDetector else None

        structured_logger.log(event_type="SERVER_START", message="FL Server Initialized (Secure Mode)")

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
        """Register a client securely"""
        if token != self.registration_token:
            logger.warning(f"Unauthorized registration attempt from {client_id}")
            return {'status': 'rejected', 'reason': 'Invalid Registration Token'}, 403

        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            self.client_keys[client_id] = public_key
        except Exception as e:
            logger.error(f"Invalid public key from {client_id}: {e}")
            return {'status': 'rejected', 'reason': 'Invalid Public Key Format'}, 400

        if client_id not in self.client_states:
            self.client_states[client_id] = {
                'registered_at': datetime.now().isoformat(),
                'updates_received': 0,
                'updates_accepted': 0,
                'updates_rejected': 0,
                'last_metrics': None,
                'attacks_detected': []
            }
            logger.info(f"Client {client_id} successfully registered with Secure Key")

        # Send Server Public Key back
        server_pub_pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return {
            'status': 'registered',
            'round': self.round,
            'client_id': client_id,
            'server_public_key': server_pub_pem
        }, 200

    def verify_signature(self, client_id, payload_bytes, signature_b64):
        """Verify the digital signature of an update"""
        if client_id not in self.client_keys:
            logger.error(f"Unknown client {client_id} attempted update")
            return False
        try:
            public_key = self.client_keys[client_id]
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, payload_bytes)
            return True
        except Exception as e:
            logger.error(f"Signature verification failed for {client_id}: {e}")
            return False

    def process_update(self, client_id, weights, metrics):
        """Process update with Security Analysis"""
        logger.info(f"Processing update from {client_id}")
        updates_received.labels(client_id=client_id).inc()

        # 1. Poisoning Detection (Model Replacement / Anomaly)
        if self.poisoning_detector:
            global_weights = self.global_model.get_weights()
            analysis = self.poisoning_detector.analyze_update(client_id, weights, global_weights)

            if analysis['is_poisoned']:
                confidence = analysis.get('confidence', 0.95)
                logger.warning(f"POISONING DETECTED from {client_id} (Conf: {confidence:.2f})")

                structured_logger.log_attack_detected(
                    attack_type="POISONING", client_id=client_id,
                    confidence=confidence, details=analysis
                )
                attack_detected.labels(type='poisoning', client_id=client_id).inc()

                self.rejected_updates.append({'client_id': client_id, 'reason': "POISONING", 'round': self.round})
                updates_rejected.labels(client_id=client_id, reason="POISONING").inc()
                return False, "POISONING_DETECTED"

        # 2. Sybil Detection (Record for Aggregation Phase)
        # We don't reject immediately here because Sybil detection needs ALL updates to compare
        if self.sybil_detector:
            self.sybil_detector.record_update(self.round, client_id, weights)

        # Store valid update
        self.client_updates[client_id] = {'weights': weights, 'metrics': metrics}
        self.client_states[client_id]['updates_accepted'] += 1
        return True, "ACCEPTED"

    def aggregate_model(self):
        if not self.client_updates:
            return False

        logger.info(f"Aggregating {len(self.client_updates)} updates...")

        # --- SYBIL DETECTION & MITIGATION ---
        client_weights_map = {cid: 1.0 for cid in self.client_updates.keys()} # Default: equal trust

        if self.sybil_detector and len(self.client_updates) >= 2:
            logger.info("Running Sybil Detection (FoolsGold)...")
            sybil_analysis = self.sybil_detector.detect_sybils(self.round)

            # Apply penalties
            foolsgold_result = self.sybil_detector.apply_foolsgold_weighting(sybil_analysis)

            for cid, info in foolsgold_result['client_weights'].items():
                if cid in self.client_updates:
                    weight = info['foolsgold_weight']
                    client_weights_map[cid] = weight

                    if weight < 0.5:
                        logger.warning(f"⬇ Penalizing Sybil Suspect {cid}: weight={weight:.2f}")
                        structured_logger.log_attack_detected(
                            attack_type="SYBIL_DETECTED",
                            client_id=cid,
                            confidence=info['reduction_ratio'],
                            round_number=self.round
                        )
                        attack_detected.labels(type='sybil', client_id=cid).inc()

        # --- WEIGHTED AGGREGATION ---
        new_weights = [np.zeros_like(w) for w in self.global_model.get_weights()]
        total_weight_score = sum(client_weights_map.values())

        if total_weight_score == 0:
            logger.error("All updates penalized to 0. Skipping aggregation.")
            return False

        for client_id, data in self.client_updates.items():
            client_w_list = data['weights']
            # Influence = Assigned Trust Weight (FoolsGold)
            influence = client_weights_map[client_id] / total_weight_score

            for i, w in enumerate(client_w_list):
                new_weights[i] += np.array(w) * influence

        self.global_model.set_weights(new_weights)

        structured_logger.log_round_end(round_number=self.round, success=True, num_clients=len(self.client_updates))
        self.client_updates.clear()
        self.round += 1
        training_round.inc()
        return True

server = FLServer()

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
    response, status_code = server.register_client(
        data.get('client_id'), data, data.get('token'), data.get('public_key')
    )
    return jsonify(response), status_code

@app.route('/get_model', methods=['POST'])
def get_model():
    """Send SIGNED global model"""
    try:
        weights = [w.tolist() for w in server.global_model.get_weights()]
        payload_content = {'weights': weights, 'round': server.round}

        payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
        signature = server.server_private_key.sign(payload_bytes)
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        return jsonify({'payload': payload_content, 'signature': signature_b64})
    except Exception as e:
        logger.error(f"Error sending model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/submit_update', methods=['POST'])
def submit_update():
    """Receive SIGNED update"""
    try:
        data_json = request.json
        payload_content = data_json.get('payload')
        signature = data_json.get('signature')
        client_id = payload_content.get('client_id')

        payload_bytes = json.dumps(payload_content, sort_keys=True).encode()

        if not server.verify_signature(client_id, payload_bytes, signature):
            structured_logger.log_error("Invalid Signature", client_id=client_id)
            return jsonify({'status': 'rejected', 'reason': 'Invalid Signature'}), 401

        weights = [np.array(w) for w in payload_content.get('weights')]
        metrics = payload_content.get('metrics')

        accepted, reason = server.process_update(client_id, weights, metrics)
        return jsonify({'status': 'accepted' if accepted else 'rejected', 'reason': reason}), 200 if accepted else 403

    except Exception as e:
        logger.error(f"Error processing update: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/trigger_round', methods=['POST'])
def trigger_round():
    structured_logger.log_round_start(server.round)
    success = server.aggregate_model()
    return jsonify({'status': 'aggregated' if success else 'skipped', 'round': server.round})

@app.route('/metrics', methods=['GET'])
def metrics():
    from prometheus_client import REGISTRY
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        'round': server.round, 'clients': server.client_states,
        'pending_updates': list(server.client_updates.keys()),
        'rejected_updates': len(server.rejected_updates)
    })

@app.route('/security/status', methods=['GET'])
def security_status():
    return jsonify({
        'security_monitoring': 'ACTIVE',
        'total_attacks_prevented': len(server.rejected_updates)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)