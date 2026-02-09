import os
import json
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import sys
import threading
import base64
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

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
        
        # Security - Token & Keys
        self.registration_token = os.getenv('REGISTRATION_TOKEN', 'default_insecure_token')
        self.client_keys = {}
        self.server_private_key = ed25519.Ed25519PrivateKey.generate()
        self.server_public_key = self.server_private_key.public_key()
        
        # DETECTION THRESHOLDS
        self.detection_config = {
            # Integrity attack detection
            'l2_multiplier': 2.0,
            'cosine_threshold': 0.5,
            'mean_ratio_threshold': 1.3,
            'std_ratio_threshold': 1.5,
            
            # Sign flip detection
            'negative_cosine_threshold': -0.3,
            
            # Gaussian noise detection
            'noise_std_multiplier': 3.0,
            
            # Backdoor detection
            'layer_divergence_threshold': 2.5,
            
            # Privacy attack detection
            'gradient_access_limit': 5,  # Max rounds a client can access
            'confidence_threshold': 0.95
        }
        
        # Historical data for detection
        self.weight_history = []
        self.client_access_count = defaultdict(int)
        
        logger.info(f" FL Server initialized for {self.max_rounds} rounds")
        logger.info(f"Detection enabled: Integrity + Privacy attacks")
    
    def _load_or_create_model(self):
        """Load pre-trained model from file, or create new one if not found"""
        h5_path = os.getenv('SERVER_MODEL_PATH', './data/global_model.h5')
        json_path = './data/global_model_weights.json'
        
        # Try JSON first
        if os.path.exists(json_path):
            try:
                logger.info(f"Loading weights from JSON: {json_path}")
                with open(json_path, 'r') as f:
                    data = json.load(f)
                
                model = self._create_model()
                weights_np = [np.array(w) for w in data['weights']]
                model.set_weights(weights_np)
                
                logger.info("Successfully loaded model weights from JSON")
                return model
            except Exception as e:
                logger.warning(f"Failed to load from JSON: {e}")

        # Try H5 as fallback
        if os.path.exists(h5_path):
            try:
                logger.info(f"Attempting to load H5 model: {h5_path}")
                model = tf.keras.models.load_model(h5_path, safe_mode=False)
                logger.info("Successfully loaded H5 model")
                return model
            except Exception as e:
                logger.warning(f"H5 load failed: {e}")
        
        # Create new
        logger.info("Creating brand new model from scratch")
        return self._create_model()

    def _create_model(self):
        """Create a new global model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(10000, 100), 
            tf.keras.layers.LSTM(150),
            tf.keras.layers.Dense(10000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        model.build(input_shape=(None, 3))
        
        logger.info("Created architecture: Embedding(10000, 100) → LSTM(150) → Dense(10000)")
        return model
 
    def register_client(self, client_id, num_samples, token=None, public_key_pem=None):
        # Verify registration token
        if token != self.registration_token:
            logger.warning(f"🔴 Unauthorized registration attempt from {client_id}")
            return {'status': 'rejected', 'reason': 'Invalid Registration Token'}, 403
        
        # Store client's public key
        if public_key_pem:
            try:
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                self.client_keys[client_id] = public_key
                logger.info(f"✓ Client {client_id} public key stored")
            except Exception as e:
                logger.error(f"Invalid public key from {client_id}: {e}")
                return {'status': 'rejected', 'reason': 'Invalid Public Key Format'}, 400
        
        if client_id not in self.client_states:
            self.client_states[client_id] = {
                'registered_at': datetime.now().isoformat(),
                'updates_received': 0,
                'updates_accepted': 0,
                'updates_rejected': 0,
                'num_samples': num_samples,
                'last_metrics': None,
                'attacks_detected': [],
                'attack_types': defaultdict(int)
            }
            logger.info(f"Client registered: {client_id} ({num_samples} samples)")
            self._log_audit('CLIENT_REGISTERED', {'client_id': client_id, 'num_samples': num_samples})
        
        # Send initial model weights
        weights = [w.tolist() for w in self.global_model.get_weights()]
        logger.info(f"Sending initial model weights to {client_id} (round {self.round})")
        
        # Send server's public key
        server_pub_pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return {
            'status': 'initialized',
            'round': self.round,
            'client_id': client_id,
            'initial_weights': weights,
            'server_public_key': server_pub_pem
        }, 200
    
    def verify_signature(self, client_id, payload_bytes, signature_b64):
        """Verify the digital signature of an update"""
        if client_id not in self.client_keys:
            logger.error(f"🔴 Unknown client {client_id} attempted update")
            return False
        
        try:
            public_key = self.client_keys[client_id]
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, payload_bytes)
            logger.info(f"✓ Signature verified for {client_id}")
            return True
        except Exception as e:
            logger.error(f"🔴 Signature verification failed for {client_id}: {e}")
            return False
    
    # ========== INTEGRITY ATTACK DETECTION ==========
    
    def detect_poisoning(self, client_id, weights, global_weights):
        """
        Multi-method poisoning detection:
        - L2 norm detection (Byzantine attacks)
        - Cosine similarity (direction attacks)
        - Statistical divergence (distribution attacks)
        """
        try:
            client_flat = np.concatenate([w.flatten() for w in weights])
            global_flat = np.concatenate([w.flatten() for w in global_weights])
            
            # METHOD 1: L2 norm detection
            l2_norm = np.linalg.norm(client_flat - global_flat)
            threshold_l2 = np.linalg.norm(global_flat) * self.detection_config['l2_multiplier']
            
            # METHOD 2: Cosine similarity
            cosine_sim = np.dot(client_flat, global_flat) / (
                np.linalg.norm(client_flat) * np.linalg.norm(global_flat) + 1e-8
            )
            threshold_cosine = self.detection_config['cosine_threshold']
            
            # METHOD 3: Statistical divergence
            mean_val = np.mean(np.abs(client_flat))
            std_val = np.std(np.abs(client_flat))
            global_mean = np.mean(np.abs(global_flat))
            global_std = np.std(np.abs(global_flat))
            
            mean_ratio = mean_val / (global_mean + 1e-8)
            std_ratio = std_val / (global_std + 1e-8)
            
            threshold_mean_ratio = self.detection_config['mean_ratio_threshold']
            threshold_std_ratio = self.detection_config['std_ratio_threshold']
            
            # Detect if ANY method triggers
            detected = False
            detection_method = []
            confidence = 0.0
            
            if l2_norm > threshold_l2:
                detected = True
                detection_method.append("L2_NORM")
                confidence = max(confidence, min(0.95, (l2_norm / threshold_l2) * 0.9))
            
            if cosine_sim < threshold_cosine:
                detected = True
                detection_method.append("COSINE_SIMILARITY")
                confidence = max(confidence, min(0.95, (1 - cosine_sim) * 0.9))
            
            if mean_ratio > threshold_mean_ratio or mean_ratio < (1 / threshold_mean_ratio):
                detected = True
                detection_method.append("MEAN_DIVERGENCE")
                confidence = max(confidence, min(0.85, abs(mean_ratio - 1) * 0.8))
            
            if std_ratio > threshold_std_ratio or std_ratio < (1 / threshold_std_ratio):
                detected = True
                detection_method.append("STD_DIVERGENCE")
                confidence = max(confidence, min(0.85, abs(std_ratio - 1) * 0.7))
            
            if detected:
                return True, confidence, {
                    'detection_methods': detection_method,
                    'l2_norm': float(l2_norm),
                    'l2_threshold': float(threshold_l2),
                    'cosine_similarity': float(cosine_sim),
                    'cosine_threshold': float(threshold_cosine),
                    'mean_ratio': float(mean_ratio),
                    'std_ratio': float(std_ratio)
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in poisoning detection: {e}")
            return False, 0.0, {}
    
    def detect_sign_flip(self, client_id, weights, global_weights):
        """
        Detect sign flip attacks (gradient ascent instead of descent).
        Check if gradients point in opposite direction.
        """
        try:
            client_flat = np.concatenate([w.flatten() for w in weights])
            global_flat = np.concatenate([w.flatten() for w in global_weights])
            
            # Compute cosine similarity
            cosine_sim = np.dot(client_flat, global_flat) / (
                np.linalg.norm(client_flat) * np.linalg.norm(global_flat) + 1e-8
            )
            
            # Negative cosine indicates opposite direction (sign flip)
            if cosine_sim < self.detection_config['negative_cosine_threshold']:
                return True, 0.9, {
                    'cosine_similarity': float(cosine_sim),
                    'detection': 'Gradient points in opposite direction (likely sign flip)'
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in sign flip detection: {e}")
            return False, 0.0, {}
    
    def detect_gaussian_noise(self, client_id, weights, global_weights):
        """
        Detect excessive Gaussian noise injection.
        Check if weight variance is unusually high.
        """
        try:
            client_flat = np.concatenate([w.flatten() for w in weights])
            global_flat = np.concatenate([w.flatten() for w in global_weights])
            
            # Compute difference
            diff = client_flat - global_flat
            
            # Check if variance of difference is unusually high
            diff_std = np.std(diff)
            global_std = np.std(global_flat)
            
            noise_ratio = diff_std / (global_std + 1e-8)
            
            if noise_ratio > self.detection_config['noise_std_multiplier']:
                return True, 0.85, {
                    'noise_ratio': float(noise_ratio),
                    'diff_std': float(diff_std),
                    'global_std': float(global_std),
                    'detection': 'Excessive noise variance detected'
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in noise detection: {e}")
            return False, 0.0, {}
    
    def detect_backdoor(self, client_id, weights, global_weights):
        """
        Detect backdoor attacks.
        Check for unusual layer-specific divergence patterns.
        """
        try:
            layer_divergences = []
            
            for i, (client_w, global_w) in enumerate(zip(weights, global_weights)):
                client_arr = np.array(client_w).flatten()
                global_arr = np.array(global_w).flatten()
                
                # Compute layer-specific L2 norm
                layer_l2 = np.linalg.norm(client_arr - global_arr)
                global_layer_l2 = np.linalg.norm(global_arr)
                
                divergence_ratio = layer_l2 / (global_layer_l2 + 1e-8)
                layer_divergences.append(divergence_ratio)
            
            # Check if last layer (output layer) has unusually high divergence
            # Backdoors often target output layer
            if len(layer_divergences) > 0:
                last_layer_divergence = layer_divergences[-1]
                avg_divergence = np.mean(layer_divergences[:-1]) if len(layer_divergences) > 1 else 0
                
                if last_layer_divergence > avg_divergence * self.detection_config['layer_divergence_threshold']:
                    return True, 0.8, {
                        'last_layer_divergence': float(last_layer_divergence),
                        'avg_other_layers': float(avg_divergence),
                        'layer_divergences': [float(d) for d in layer_divergences],
                        'detection': 'Unusual output layer divergence (backdoor pattern)'
                    }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in backdoor detection: {e}")
            return False, 0.0, {}
    
    def detect_model_replacement(self, client_id, weights, global_weights):
        """
        Detect MODEL_REPLACEMENT attacks.
        Check if entire model structure differs significantly from global.
        """
        try:
            # Check if ALL layers diverge significantly
            all_divergent = True
            divergence_scores = []
            
            for client_w, global_w in zip(weights, global_weights):
                client_arr = np.array(client_w).flatten()
                global_arr = np.array(global_w).flatten()
                
                # Compute correlation
                correlation = np.corrcoef(client_arr, global_arr)[0, 1]
                divergence_scores.append(1 - correlation)  # Higher = more divergent
            
            # If all layers are divergent, likely model replacement
            avg_divergence = np.mean(divergence_scores)
            
            if avg_divergence > 0.7:  # 70% divergence across all layers
                return True, 0.90, {
                    'avg_divergence': float(avg_divergence),
                    'layer_divergences': [float(d) for d in divergence_scores],
                    'detection': 'Entire model structure divergent (model replacement)'
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in model replacement detection: {e}")
            return False, 0.0, {}
    
    def detect_malicious_aggregation(self, client_id, weights, global_weights):
        """
        Detect MALICIOUS_AGGREGATION attacks.
        Check for carefully crafted updates designed to exploit averaging.
        """
        try:
            client_flat = np.concatenate([w.flatten() for w in weights])
            global_flat = np.concatenate([w.flatten() for w in global_weights])
            
            # Check if update has unusual directionality
            diff = client_flat - global_flat
            
            # Compute entropy of differences (uniform direction = low entropy)
            hist, _ = np.histogram(diff, bins=50)
            hist = hist / (np.sum(hist) + 1e-8)
            entropy = -np.sum(hist * np.log(hist + 1e-8))
            
            # Low entropy = coordinated attack
            if entropy < 2.5:
                return True, 0.75, {
                    'entropy': float(entropy),
                    'detection': 'Low-entropy directional update (malicious aggregation)'
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in malicious aggregation detection: {e}")
            return False, 0.0, {}
    
    def detect_model_drift(self, client_id, weights):
        """
        Detect MODEL_DRIFT attacks.
        Track if client consistently deviates in same direction over rounds.
        """
        try:
            # Need historical data
            if len(self.weight_history) < 3:
                return False, 0.0, {}
            
            # Get client's last 3 updates
            client_updates = []
            for hist in self.weight_history[-3:]:
                if client_id in hist:
                    client_updates.append(hist[client_id])
            
            if len(client_updates) < 3:
                return False, 0.0, {}
            
            # Compute directions of changes
            directions = []
            for i in range(len(client_updates) - 1):
                curr = np.concatenate([np.array(w).flatten() for w in client_updates[i]])
                next_w = np.concatenate([np.array(w).flatten() for w in client_updates[i+1]])
                direction = next_w - curr
                direction = direction / (np.linalg.norm(direction) + 1e-8)
                directions.append(direction)
            
            # Check if directions are consistent (drift)
            if len(directions) >= 2:
                similarity = np.dot(directions[0], directions[1])
                if similarity > 0.9:  # Very consistent direction
                    return True, 0.70, {
                        'direction_similarity': float(similarity),
                        'detection': 'Consistent directional drift across rounds'
                    }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in drift detection: {e}")
            return False, 0.0, {}
    
    def detect_free_riding(self, client_id, weights, global_weights):
        """
        Detect FREE_RIDING attacks.
        Check if updates are suspiciously minimal/fake.
        """
        try:
            client_flat = np.concatenate([w.flatten() for w in weights])
            global_flat = np.concatenate([w.flatten() for w in global_weights])
            
            # Compute magnitude of update
            update_magnitude = np.linalg.norm(client_flat - global_flat)
            global_magnitude = np.linalg.norm(global_flat)
            
            # Relative update size
            relative_update = update_magnitude / (global_magnitude + 1e-8)
            
            # If update is suspiciously tiny (< 0.001% of model)
            if relative_update < 0.00001:
                return True, 0.65, {
                    'relative_update_size': float(relative_update),
                    'detection': 'Suspiciously minimal update (free-riding)'
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in free-riding detection: {e}")
            return False, 0.0, {}
    
    def detect_data_poisoning(self, client_id, metrics):
        """
        Detect DATA_POISONING attacks.
        Check for unusual training metrics that indicate corrupted data.
        """
        try:
            if 'loss' not in metrics or 'accuracy' not in metrics:
                return False, 0.0, {}
            
            loss = metrics['loss']
            accuracy = metrics['accuracy']
            
            # Suspiciously high loss or low accuracy
            if loss > 10.0 or accuracy < 0.01:
                return True, 0.75, {
                    'loss': loss,
                    'accuracy': accuracy,
                    'detection': 'Abnormal training metrics (data poisoning)'
                }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in data poisoning detection: {e}")
            return False, 0.0, {}
    
    def detect_adversarial_examples(self, client_id, weights, global_weights):
        """
        Detect ADVERSARIAL_EXAMPLES in training.
        Similar to noise detection but with specific patterns.
        """
        try:
            client_flat = np.concatenate([w.flatten() for w in weights])
            global_flat = np.concatenate([w.flatten() for w in global_weights])
            
            diff = client_flat - global_flat
            
            # Adversarial examples create specific high-frequency patterns
            # Check for unusual variance patterns
            chunk_size = 1000
            chunk_vars = []
            for i in range(0, len(diff), chunk_size):
                chunk = diff[i:i+chunk_size]
                if len(chunk) > 0:
                    chunk_vars.append(np.var(chunk))
            
            if len(chunk_vars) > 1:
                var_of_vars = np.var(chunk_vars)
                mean_var = np.mean(chunk_vars)
                
                # High variance of variances indicates adversarial patterns
                if var_of_vars / (mean_var + 1e-8) > 5.0:
                    return True, 0.70, {
                        'variance_ratio': float(var_of_vars / (mean_var + 1e-8)),
                        'detection': 'High-frequency variance patterns (adversarial examples)'
                    }
            
            return False, 0.0, {}
        except Exception as e:
            logger.error(f"Error in adversarial examples detection: {e}")
            return False, 0.0, {}
    
    # ========== PRIVACY ATTACK DETECTION ==========
    
    def detect_gradient_inversion(self, client_id):
        """
        Detect gradient inversion attempts.
        Monitor if client is accessing gradients too frequently.
        """
        self.client_access_count[client_id] += 1
        
        if self.client_access_count[client_id] > self.detection_config['gradient_access_limit']:
            return True, 0.7, {
                'access_count': self.client_access_count[client_id],
                'limit': self.detection_config['gradient_access_limit'],
                'detection': 'Excessive gradient access (potential inversion attack)'
            }
        
        return False, 0.0, {}
    
    def detect_membership_inference(self, client_id, metrics):
        """
        Detect membership inference attempts.
        Check if client is probing with unusually high confidence queries.
        """
        if 'accuracy' in metrics:
            accuracy = metrics['accuracy']
            
            # Very high accuracy might indicate overfitting/probing
            if accuracy > self.detection_config['confidence_threshold']:
                return True, 0.6, {
                    'accuracy': accuracy,
                    'threshold': self.detection_config['confidence_threshold'],
                    'detection': 'Unusually high accuracy (potential membership inference)'
                }
        
        return False, 0.0, {}
    
    def detect_property_inference(self, client_id, weights):
        """
        Detect property inference attempts.
        Monitor for patterns indicating statistical analysis of weights.
        """
        # Store weight statistics
        if len(self.weight_history) > 3:
            # Check if client is repeatedly analyzing same patterns
            recent_weights = self.weight_history[-3:]
            
            # Simple heuristic: check variance in weight updates
            variances = []
            for w_hist in recent_weights:
                if client_id in w_hist:
                    client_weights = w_hist[client_id]
                    flat_weights = np.concatenate([np.array(w).flatten() for w in client_weights])
                    variances.append(np.var(flat_weights))
            
            if len(variances) >= 3:
                # If variance is suspiciously stable, might be probing
                variance_std = np.std(variances)
                if variance_std < 1e-6:
                    return True, 0.65, {
                        'variance_stability': float(variance_std),
                        'detection': 'Stable weight variance (potential property inference)'
                    }
        
        return False, 0.0, {}
    
    def process_update(self, client_id, weights, metrics):
        """Process and analyze client update with comprehensive detection"""
        logger.info(f"Processing update from {client_id} (Round {self.round})")
        
        self.client_states[client_id]['updates_received'] += 1
        self.client_states[client_id]['last_metrics'] = metrics
        
        global_weights = self.global_model.get_weights()
        
        # Run all detection methods
        detected_attacks = []
        total_confidence = 0.0
        
        # INTEGRITY ATTACK DETECTION
        is_poisoned, conf, details = self.detect_poisoning(client_id, weights, global_weights)
        if is_poisoned:
            detected_attacks.append({
                'type': 'POISONING',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        is_sign_flip, conf, details = self.detect_sign_flip(client_id, weights, global_weights)
        if is_sign_flip:
            detected_attacks.append({
                'type': 'SIGN_FLIP',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        is_noise, conf, details = self.detect_gaussian_noise(client_id, weights, global_weights)
        if is_noise:
            detected_attacks.append({
                'type': 'GAUSSIAN_NOISE',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        is_backdoor, conf, details = self.detect_backdoor(client_id, weights, global_weights)
        if is_backdoor:
            detected_attacks.append({
                'type': 'BACKDOOR',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # NEW: MODEL_REPLACEMENT detection
        is_replacement, conf, details = self.detect_model_replacement(client_id, weights, global_weights)
        if is_replacement:
            detected_attacks.append({
                'type': 'MODEL_REPLACEMENT',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # NEW: MALICIOUS_AGGREGATION detection
        is_mal_agg, conf, details = self.detect_malicious_aggregation(client_id, weights, global_weights)
        if is_mal_agg:
            detected_attacks.append({
                'type': 'MALICIOUS_AGGREGATION',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # NEW: MODEL_DRIFT detection
        is_drift, conf, details = self.detect_model_drift(client_id, weights)
        if is_drift:
            detected_attacks.append({
                'type': 'MODEL_DRIFT',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # NEW: FREE_RIDING detection
        is_free_ride, conf, details = self.detect_free_riding(client_id, weights, global_weights)
        if is_free_ride:
            detected_attacks.append({
                'type': 'FREE_RIDING',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # NEW: DATA_POISONING detection
        is_data_poison, conf, details = self.detect_data_poisoning(client_id, metrics)
        if is_data_poison:
            detected_attacks.append({
                'type': 'DATA_POISONING',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # NEW: ADVERSARIAL_EXAMPLES detection
        is_adv_examples, conf, details = self.detect_adversarial_examples(client_id, weights, global_weights)
        if is_adv_examples:
            detected_attacks.append({
                'type': 'ADVERSARIAL_EXAMPLES',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # PRIVACY ATTACK DETECTION
        is_grad_inv, conf, details = self.detect_gradient_inversion(client_id)
        if is_grad_inv:
            detected_attacks.append({
                'type': 'GRADIENT_INVERSION',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        is_mem_inf, conf, details = self.detect_membership_inference(client_id, metrics)
        if is_mem_inf:
            detected_attacks.append({
                'type': 'MEMBERSHIP_INFERENCE',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        is_prop_inf, conf, details = self.detect_property_inference(client_id, weights)
        if is_prop_inf:
            detected_attacks.append({
                'type': 'PROPERTY_INFERENCE',
                'confidence': conf,
                'details': details
            })
            total_confidence = max(total_confidence, conf)
        
        # Log analysis
        analysis = {
            'round': self.round,
            'client_id': client_id,
            'timestamp': datetime.now().isoformat(),
            'attacks_detected': detected_attacks,
            'overall_confidence': float(total_confidence),
            'metrics': metrics
        }
        self._log_audit('UPDATE_ANALYZED', analysis)
        
        # If any attack detected, reject update
        if detected_attacks:
            attack_types = [a['type'] for a in detected_attacks]
            logger.warning(f"🔴 ATTACKS DETECTED from {client_id}: {', '.join(attack_types)} (confidence={total_confidence:.2f})")
            
            self.detected_attacks.append(analysis)
            self.client_states[client_id]['attacks_detected'].append({
                'round': self.round,
                'confidence': total_confidence,
                'attacks': detected_attacks
            })
            
            # Track attack types
            for attack_type in attack_types:
                self.client_states[client_id]['attack_types'][attack_type] += 1
            
            self.client_states[client_id]['updates_rejected'] += 1
            return False, f"ATTACKS_DETECTED: {', '.join(attack_types)}"
        
        # Store valid update
        self.client_updates[client_id] = {
            'weights': weights,
            'metrics': metrics,
            'timestamp': datetime.now()
        }
        
        # Store weight history for property inference detection
        if self.round not in [w.get('round') for w in self.weight_history]:
            self.weight_history.append({
                'round': self.round,
                client_id: weights
            })
        
        self.client_states[client_id]['updates_accepted'] += 1
        logger.info(f"✓ Update accepted from {client_id}")
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
            'round': self.round - 1,
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
    
    response, status_code = server.register_client(
        client_id, 
        num_samples,
        token=data.get('token'),
        public_key_pem=data.get('public_key')
    )
    return jsonify(response), status_code

@app.route('/get_model', methods=['POST'])
def get_model():
    """Send SIGNED global model weights to client"""
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
        return jsonify({'error': str(e)}), 500

@app.route('/submit_update', methods=['POST'])
def submit_update():
    """Receive SIGNED model update from client with attack detection"""
    try:
        data = request.json
        
        # Handle signed payload
        if 'payload' in data and 'signature' in data:
            payload_content = data['payload']
            signature = data['signature']
            client_id = payload_content.get('client_id')
            
            # Verify signature
            payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
            if not server.verify_signature(client_id, payload_bytes, signature):
                return jsonify({
                    'status': 'rejected',
                    'reason': 'Invalid Signature'
                }), 401
            
            weights = [np.array(w) for w in payload_content.get('weights', [])]
            metrics = payload_content.get('metrics', {})
        else:
            # Backward compatibility
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
    
    event = server.waiting_clients[client_id]
    signaled = event.wait(timeout=300)
    
    if signaled:
        event.clear()
        return jsonify({'status': 'go_train', 'round': server.round})
    else:
        return jsonify({'status': 'timeout'}), 408

@app.route('/trigger_round', methods=['POST'])
def trigger_round():
    """Trigger a training round"""
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
    attack_summary = defaultdict(int)
    for attack in server.detected_attacks:
        for detected in attack['attacks_detected']:
            attack_summary[detected['type']] += 1
    
    return jsonify({
        'monitoring': 'ACTIVE',
        'total_attacks_detected': len(server.detected_attacks),
        'attack_types_summary': dict(attack_summary),
        'recent_attacks': server.detected_attacks[-10:] if len(server.detected_attacks) > 10 else server.detected_attacks
    })

if __name__ == '__main__':
    logger.info("Starting FL Server with Multi-Attack Detection")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)