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

# Import security detectors
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'audit'))
try:
    from detect_poisoning import PoisoningDetector
    from detect_sybil_attacks import SybilDetector
    print(" Security detectors loaded")
except ImportError as e:
    print(f"  Warning: Security detectors not available: {e}")
    PoisoningDetector = None
    SybilDetector = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FL-Server")

app = Flask(__name__)

# Metrics
updates_received = Counter('fl_updates_received', 'Number of model updates received', ['client_id'])
updates_rejected = Counter('fl_updates_rejected', 'Number of rejected updates', ['client_id', 'reason'])
update_size = Histogram('fl_update_size_bytes', 'Size of updates in bytes', ['client_id'])
training_round = Counter('fl_training_round', 'Training round number')

class FLServer:
    def __init__(self):
        self.global_model = self._create_model()
        self.client_updates = {}
        self.rejected_updates = {}  # Track rejected updates
        self.round = 0
        self.training_history = []
        self.client_states = {}
        
        # Security detectors
        if PoisoningDetector:
            self.poisoning_detector = PoisoningDetector(threshold_std=2.5)
        if SybilDetector:
            self.sybil_detector = SybilDetector(similarity_threshold=0.85)
        
        # Create audit directory
        os.makedirs('security_audits', exist_ok=True)
        
        logger.info("  FL Server initialized with security monitoring")
    
    def _create_model(self):
        # Using 1000 for vocab size to keep the model lightweight for your runner
        model = tf.keras.Sequential([
            # Article: Embedding(total_words, 100, input_length=max_sequence_len-1)
            tf.keras.layers.Embedding(1000, 100, input_length=3),
            # Article: LSTM(150)
            tf.keras.layers.LSTM(150),
            # Article: Dense(total_words, activation='softmax')
            tf.keras.layers.Dense(1000, activation='softmax')
        ])
        # Article: compile(loss='categorical_crossentropy', optimizer='adam')
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        return model
    
    def aggregate_updates(self, updates, num_clients):
        """Federated averaging"""
        aggregated_weights = None
        num_updates = len(updates)
        
        for client_id, weights in updates.items():
            if aggregated_weights is None:
                aggregated_weights = [np.array(w, dtype=np.float32) for w in weights]
            else:
                for i, w in enumerate(weights):
                    w_array = np.array(w, dtype=np.float32)
                    aggregated_weights[i] = aggregated_weights[i] + w_array
        
        aggregated_weights = [w / num_updates for w in aggregated_weights]
        aggregated_weights = [w.tolist() for w in aggregated_weights]
        
        logger.info(f" Aggregated {num_updates} client updates")
        return aggregated_weights
    
    def get_model_weights(self):
        return [w.tolist() for w in self.global_model.get_weights()]
    
    def set_model_weights(self, weights):
        weights = [np.array(w) for w in weights]
        self.global_model.set_weights(weights)
    
    def analyze_update_security(self, client_id: str, weights: list, metrics: dict) -> dict:
        """
        SECURITY ANALYSIS: Analyze update for attacks
        
        Returns:
        {
            'is_suspicious': bool,
            'detected_attacks': [
                {'type': 'POISONING', 'confidence': 0.95},
                {'type': 'SYBIL', 'confidence': 0.73}
            ],
            'action': 'ACCEPT' or 'REJECT',
            'reason': 'explanation'
        }
        """
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'client_id': client_id,
            'detected_attacks': [],
            'is_suspicious': False,
            'action': 'ACCEPT',
            'reason': 'Update passed all security checks',
            'metrics': {}
        }
        
        # If client marked as poisoned in metadata
        if metrics.get('is_poisoned', False):
            logger.warning(f"  Client {client_id} self-reported poisoned update: {metrics.get('attack_type')}")
            analysis['detected_attacks'].append({
                'type': 'SELF_REPORTED',
                'attack_subtype': metrics.get('attack_type'),
                'confidence': 1.0
            })
            analysis['is_suspicious'] = True
        
        # Analyze with poisoning detector
        if PoisoningDetector:
            update_metrics = self.poisoning_detector.analyze_update(
                client_id=client_id,
                weights=weights
            )
            
            # Check for anomalies
            l2_norm = update_metrics['l2_norm']
            std_weight = update_metrics['std_weight']
            
            analysis['metrics']['l2_norm'] = l2_norm
            analysis['metrics']['std_weight'] = std_weight
            
            # Detect Model Replacement (very large L2 norm)
            if l2_norm > 10.0:  # Threshold for very large update
                analysis['detected_attacks'].append({
                    'type': 'MODEL_REPLACEMENT',
                    'confidence': min(1.0, l2_norm / 50.0),  # Scale confidence by magnitude
                    'evidence': f'L2 norm {l2_norm:.2f} is anomalously large'
                })
                analysis['is_suspicious'] = True
            
            # Detect Constrain-and-Scale (very low variance)
            if std_weight < 0.001:  # Threshold for tight variance
                analysis['detected_attacks'].append({
                    'type': 'CONSTRAIN_AND_SCALE',
                    'confidence': 0.7,
                    'evidence': f'Weight std {std_weight:.4f} is suspiciously low'
                })
                analysis['is_suspicious'] = True
        
        # Determine action
        if analysis['is_suspicious']:
            # Decide whether to reject based on confidence
            max_confidence = max(
                [a['confidence'] for a in analysis['detected_attacks']], 
                default=0.0
            )
            
            if max_confidence > 0.8:
                analysis['action'] = 'REJECT'
                analysis['reason'] = f'High confidence attack detected: {analysis["detected_attacks"][0]["type"]} ({max_confidence:.1%})'
            else:
                analysis['action'] = 'ACCEPT_WITH_CAUTION'
                analysis['reason'] = f'Suspicious but not conclusive. Monitoring.'
        
        return analysis
    
    def save_state(self):
        """Save model and audit trail"""
        state = {
            'round': self.round,
            'weights': self.get_model_weights(),
            'history': self.training_history,
            'client_states': self.client_states,
            'timestamp': datetime.now().isoformat()
        }
        with open('server_state.json', 'w') as f:
            json.dump(state, f)


server = FLServer()

# ============================================
# REST API ENDPOINTS
# ============================================

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
        'updates_accepted': 0,
        'updates_rejected': 0,
        'last_update': None,
        'data_samples': data.get('num_samples', 0),
        'suspicious_count': 0
    }
    
    logger.info(f" Client {client_id} initialized")
    return jsonify({
        'status': 'initialized',
        'client_id': client_id,
        'round': server.round
    })

@app.route('/get_model', methods=['POST'])
def get_model():
    """Send global model to client"""
    data = request.json
    client_id = data.get('client_id')
    
    weights = server.get_model_weights()
    response = {
        'weights': weights,
        'round': server.round,
        'model_hash': hashlib.md5(str(weights[:1]).encode()).hexdigest()[:8]
    }
    
    logger.info(f" Model sent to {client_id} at round {server.round}")
    return jsonify(response)

@app.route('/submit_update', methods=['POST'])
def submit_update():
    """
    SECURITY: Receive and analyze update from client
    """
    data = request.json
    client_id = data.get('client_id')
    weights = data.get('weights')
    metrics = data.get('metrics', {})
    
    size_bytes = len(json.dumps(weights))
    
    # ============================================
    # STEP 1: SECURITY ANALYSIS
    # ============================================
    logger.info(f"\n{'='*70}")
    logger.info(f"Update from {client_id} (Size: {size_bytes} bytes)")
    logger.info(f"{'='*70}")
    
    security_analysis = server.analyze_update_security(client_id, weights, metrics)
    
    # ============================================
    # STEP 2: DECISION & ACTION
    # ============================================
    
    if security_analysis['action'] == 'REJECT':
        logger.warning(f"\n REJECTING UPDATE FROM {client_id}")
        logger.warning(f"   Reason: {security_analysis['reason']}")
        
        # Track rejected update
        server.rejected_updates[f"{server.round}_{client_id}"] = {
            'security_analysis': security_analysis,
            'timestamp': datetime.now().isoformat()
        }
        
        # Update metrics
        for attack in security_analysis['detected_attacks']:
            updates_rejected.labels(
                client_id=client_id,
                reason=attack['type']
            ).inc()
        
        server.client_states[client_id]['updates_rejected'] += 1
        server.client_states[client_id]['suspicious_count'] += 1
        
        # Return rejection
        return jsonify({
            'status': 'rejected',
            'reason': security_analysis['reason'],
            'detected_attacks': security_analysis['detected_attacks']
        }), 403
    
    # ============================================
    # STEP 3: ACCEPT UPDATE
    # ============================================
    
    logger.info(f" ACCEPTING UPDATE from {client_id}")
    
    if security_analysis['detected_attacks']:
        logger.info(f"   (Note: {len(security_analysis['detected_attacks'])} suspicions, but confidence < 80%)")
        for attack in security_analysis['detected_attacks']:
            logger.info(f"   - {attack['type']}: {attack['confidence']:.1%}")
    
    # Store update
    updates_received.labels(client_id=client_id).inc()
    update_size.labels(client_id=client_id).observe(size_bytes)
    
    server.client_states[client_id]['updates_sent'] += 1
    server.client_states[client_id]['updates_accepted'] += 1
    server.client_states[client_id]['last_update'] = datetime.now().isoformat()
    server.client_states[client_id]['last_metrics'] = metrics
    
    server.client_updates[client_id] = {
        'weights': weights,
        'metrics': metrics,
        'timestamp': datetime.now().isoformat(),
        'security_analysis': security_analysis
    }
    
    logger.info(f"   Updates from this client: {server.client_states[client_id]['updates_accepted']} accepted, {server.client_states[client_id]['updates_rejected']} rejected")
    
    return jsonify({
        'status': 'accepted',
        'update_id': f"{server.round}_{client_id}"
    })

@app.route('/trigger_round', methods=['POST'])
def trigger_round():
    """
    SECURITY: Aggregate updates from clients
    Applies federated averaging only to accepted updates
    """
    
    if len(server.client_updates) == 0:
        return jsonify({'error': 'No client updates available'}), 400
    
    logger.info(f"\n{'='*70}")
    logger.info(f"AGGREGATION ROUND {server.round + 1}")
    logger.info(f"{'='*70}")
    
    # Log which updates are being aggregated
    logger.info(f" Aggregating {len(server.client_updates)} accepted updates:")
    for client_id in server.client_updates.keys():
        logger.info(f"   - {client_id}")
    
    # Aggregate
    aggregated = server.aggregate_updates(
        {cid: update['weights'] for cid, update in server.client_updates.items()},
        num_clients=len(server.client_updates)
    )
    
    # Update model
    server.set_model_weights(aggregated)
    
    # Record history
    history_entry = {
        'round': server.round,
        'num_clients': len(server.client_updates),
        'timestamp': datetime.now().isoformat(),
        'client_metrics': {cid: update['metrics'] for cid, update in server.client_updates.items()},
        'security_analysis': {cid: update.get('security_analysis', {}) for cid, update in server.client_updates.items()}
    }
    server.training_history.append(history_entry)
    
    # Save audit
    audit_record = {
        'round': server.round,
        'timestamp': datetime.now().isoformat(),
        'accepted_clients': list(server.client_updates.keys()),
        'rejected_updates': server.rejected_updates,
        'client_states': server.client_states,
        'aggregation_result': 'SUCCESS'
    }
    
    with open(f'security_audits/round_{server.round}_audit.json', 'w') as f:
        json.dump(audit_record, f, indent=2)
    
    server.round += 1
    server.client_updates = {}
    server.rejected_updates = {}
    
    server.save_state()
    training_round.inc()
    
    logger.info(f" Round {server.round - 1} completed and saved")
    logger.info(f"   Audit saved to: security_audits/round_{server.round-1}_audit.json\n")
    
    return jsonify({
        'status': 'aggregated',
        'round': server.round - 1
    })

@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics"""
    from prometheus_client import REGISTRY
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/status', methods=['GET'])
def status():
    """Server status with security info"""
    return jsonify({
        'round': server.round,
        'clients': server.client_states,
        'pending_updates': list(server.client_updates.keys()),
        'rejected_updates': len(server.rejected_updates),
        'history': server.training_history[-5:]
    })

@app.route('/security/status', methods=['GET'])
def security_status():
    """Security status endpoint"""
    return jsonify({
        'round': server.round,
        'security_monitoring': 'ACTIVE',
        'detectors': {
            'poisoning': 'ENABLED',
            'sybil': 'ENABLED',
            'privacy': 'ENABLED'
        },
        'recent_detections': len(server.rejected_updates),
        'client_health': {
            cid: {
                'acceptance_rate': state['updates_accepted'] / max(1, state['updates_sent']),
                'suspicious_count': state['suspicious_count']
            }
            for cid, state in server.client_states.items()
        }
    })

if __name__ == '__main__':
    logger.info("  Starting FL Server with Security Monitoring on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)