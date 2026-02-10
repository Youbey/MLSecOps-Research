import os
import sys
import json
import numpy as np
import tensorflow as tf
import requests
import time
import logging
import base64
from datetime import datetime
from typing import Literal
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class MaliciousClient:
    """
    Malicious client implementing AGGRESSIVE attack types from FL taxonomy.
    
    INTEGRITY ATTACKS:
    - DATA_POISONING: Corrupt training data heavily
    - MODEL_POISONING: Manipulate model updates aggressively (Byzantine)
    - BACKDOOR: Inject strong backdoor trigger patterns
    - LABEL_FLIP: Flip training labels completely
    
    PRIVACY ATTACKS:
    - GRADIENT_INVERSION: Reconstruct training data from gradients
    - MEMBERSHIP_INFERENCE: Infer if data was in training set
    - PROPERTY_INFERENCE: Infer dataset properties
    
    AGGREGATOR/SERVER ATTACKS:
    - MODEL_REPLACEMENT: Replace entire model with adversarial version
    - MALICIOUS_AGGREGATION: Craft extreme updates to exploit aggregation
    
    ADVERSARIAL/ROBUSTNESS ATTACKS:
    - ADVERSARIAL_EXAMPLES: Add strong adversarial perturbations
    - MODEL_DRIFT: Cause significant model drift
    - FREE_RIDING: Submit minimal/fake updates
    
    STEALTHY: Combination attack that tries to be more subtle
    """
    
    def __init__(self, client_id, server_url, data_file, attack_mode='NONE'):
        self.client_id = client_id
        self.server_url = server_url
        self.attack_mode = attack_mode
        
        self.logger = logging.getLogger(f"CLIENT-{client_id}")
        
        # Security
        self.registration_token = os.getenv('REGISTRATION_TOKEN')
        self.server_public_key = None
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Model
        self.model = self._create_model()
        
        # Data
        self.training_data = self._load_data(data_file)
        self.original_data = self._load_data(data_file)  # Keep clean copy
        
        # Attack tracking
        self.intercepted_gradients = []
        self.attack_history = []
        self.free_riding_mode = False
        
        self.logger.info(f"⚠️  Initialized MALICIOUS client (attack_mode={attack_mode})")
        
        self._register_with_server()
    
    def _create_model(self):
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(10000, 100, input_length=3),
            tf.keras.layers.LSTM(150),
            tf.keras.layers.Dense(10000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        model.build(input_shape=(None, 3))
        return model
    
    def _load_data(self, data_file):
        with open(data_file, 'r') as f:
            data = json.load(f)
        data_array = np.array(data)
        X = data_array[:, :-1]
        y = data_array[:, -1]
        self.logger.info(f"Loaded {len(X)} training samples")
        return X, y
    
    def _register_with_server(self):
        try:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            response = requests.post(
                f'{self.server_url}/init_client',
                json={
                    'client_id': self.client_id,
                    'num_samples': len(self.training_data[0]),
                    'public_key': pem,
                    'token': self.registration_token
                }
            )
            
            data = response.json()
            
            if 'server_public_key' in data:
                self.server_public_key = serialization.load_pem_public_key(
                    data['server_public_key'].encode()
                )
                self.logger.info("Server public key received")
            
            if 'initial_weights' in data:
                weights = [np.array(w) for w in data['initial_weights']]
                self.model.set_weights(weights)
                self.logger.info(f"✓ Registered with server")
                
        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
    
    def fetch_model(self):
        """Fetch global model"""
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            data = response.json()
            
            # Verify signature
            if self.server_public_key and 'signature' in data:
                try:
                    payload_content = data['payload']
                    signature = base64.b64decode(data['signature'])
                    payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
                    self.server_public_key.verify(signature, payload_bytes)
                    
                    weights = [np.array(w) for w in payload_content['weights']]
                except Exception as e:
                    self.logger.critical(f"🔴 Server signature INVALID! {e}")
                    return False
            else:
                weights = [np.array(w) for w in data['weights']]
            
            self.model.set_weights(weights)
            
            # Store for privacy attacks
            if self.attack_mode in ['GRADIENT_INVERSION', 'MEMBERSHIP_INFERENCE', 'PROPERTY_INFERENCE', 'STEALTHY']:
                self.intercepted_gradients.append({
                    'weights': weights
                })
            
            self.logger.info(f"✓ Fetched model")
            return True
        except Exception as e:
            self.logger.error(f"Failed to fetch model: {e}")
            return False
    
    def train_locally(self, epochs=2):
        """Train with potential data attacks"""
        self.logger.info(f"Starting local training ({epochs} epochs)")
        
        # FREE_RIDING: Skip training entirely
        if self.attack_mode == 'FREE_RIDING':
            self.logger.warning(f"🔴 FREE_RIDING: Skipping training, will submit fake updates")
            return 0.0, 0.0
        
        X, y = self.training_data
        
        # DATA_POISONING: Use heavily corrupted data
        if self.attack_mode == 'DATA_POISONING' or self.attack_mode == 'POISONING':
            X, y = self._attack_data_poisoning(X, y)
        
        # LABEL_FLIP: Completely flip labels
        elif self.attack_mode == 'LABEL_FLIP':
            y = self._attack_label_flip(y)
        
        # ADVERSARIAL_EXAMPLES: Add strong adversarial perturbations
        elif self.attack_mode == 'ADVERSARIAL_EXAMPLES':
            X = self._attack_adversarial_examples(X)
        
        # STEALTHY: Subtle data corruption
        elif self.attack_mode == 'STEALTHY':
            X, y = self._attack_stealthy_data(X, y)
        
        history = self.model.fit(
            X, y,
            epochs=epochs,
            batch_size=8,
            verbose=0,
            validation_split=0.2
        )
        
        loss = float(history.history['loss'][-1])
        accuracy = float(history.history['accuracy'][-1])
        
        self.logger.info(f"Training completed - loss={loss:.4f}, accuracy={accuracy:.4f}")
        return loss, accuracy
    
    # ========== INTEGRITY ATTACKS (AGGRESSIVE) ==========
    
    def _attack_data_poisoning(self, X, y):
        """
        AGGRESSIVE DATA_POISONING: Heavily corrupt training data.
        This should result in very high loss and low accuracy.
        """
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE DATA_POISONING ATTACK")
        
        # Add MASSIVE noise to features
        noise_level = 2.0  # Was 0.3 - now 2.0 (very aggressive)
        X_poisoned = X + np.random.normal(0, noise_level, X.shape)
        
        # Flip MOST labels (80%)
        flip_ratio = 0.8  # Was 0.2 - now 0.8
        num_flip = int(len(y) * flip_ratio)
        flip_indices = np.random.choice(len(y), num_flip, replace=False)
        y_poisoned = y.copy()
        y_poisoned[flip_indices] = np.random.randint(0, 10, num_flip)
        
        self.logger.warning(f"💥 Corrupted {num_flip} samples ({flip_ratio*100}%) with heavy noise")
        return X_poisoned, y_poisoned
    
    def _attack_label_flip(self, labels):
        """AGGRESSIVE LABEL_FLIP: Completely reverse all labels"""
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE LABEL_FLIP ATTACK")
        num_classes = int(np.max(labels)) + 1
        # Completely reverse the labels
        flipped = (num_classes - 1 - labels) % num_classes
        self.logger.warning(f"💥 Flipped ALL {len(labels)} labels (complete reversal)")
        return flipped
    
    def _attack_model_poisoning(self, weights):
        """
        AGGRESSIVE MODEL_POISONING: Byzantine attack with MASSIVE scaling.
        This should be very obvious to detect.
        """
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE MODEL_POISONING ATTACK")
        gamma = 1000.0  # Was 100.0 - now 1000.0 (10x more aggressive)
        poisoned = [(np.array(w) * gamma).tolist() for w in weights]
        self.logger.warning(f"💥 Scaled weights by MASSIVE gamma={gamma}")
        return poisoned
    
    def _attack_backdoor(self, weights):
        """
        AGGRESSIVE BACKDOOR: Inject STRONG trigger pattern in output layer.
        """
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE BACKDOOR ATTACK")
        
        backdoored = []
        for i, w in enumerate(weights):
            w_arr = np.array(w)
            if i == len(weights) - 1:  # Output layer
                # Much stronger trigger pattern
                trigger_pattern = np.random.uniform(-1.0, 1.0, w_arr.shape)  # Was ±0.1, now ±1.0
                w_backdoor = w_arr + trigger_pattern * 10.0  # Was 2.0, now 10.0
            else:
                w_backdoor = w_arr
            backdoored.append(w_backdoor.tolist())
        
        self.logger.warning(f"💥 Injected STRONG backdoor trigger in output layer")
        return backdoored
    
    # ========== AGGREGATOR/SERVER ATTACKS (AGGRESSIVE) ==========
    
    def _attack_model_replacement(self, weights):
        """
        AGGRESSIVE MODEL_REPLACEMENT: Replace with completely adversarial model.
        """
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE MODEL_REPLACEMENT ATTACK")
        
        # Create adversarial model
        adversarial_model = self._create_model()
        X, y = self.original_data
        
        # Completely reverse labels for adversarial training
        y_adv = (10 - 1 - y) % 10  # Complete reversal
        
        adversarial_model.fit(X, y_adv, epochs=3, batch_size=8, verbose=0)  # More epochs
        
        # Get adversarial weights
        adv_weights = [w.tolist() for w in adversarial_model.get_weights()]
        
        # Scale MASSIVELY to dominate aggregation
        scale_factor = 100.0  # Was 10.0 - now 100.0
        replaced = [(np.array(w) * scale_factor).tolist() for w in adv_weights]
        
        self.logger.warning(f"💥 Replaced model with STRONG adversarial version (scaled by {scale_factor})")
        return replaced
    
    def _attack_malicious_aggregation(self, weights):
        """
        AGGRESSIVE MALICIOUS_AGGREGATION: Create updates with VERY low entropy.
        This creates a uniform directional attack that should be easily detected.
        """
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE MALICIOUS_AGGREGATION ATTACK")
        
        malicious = []
        # Create a SINGLE direction for ALL weights (very low entropy)
        global_direction = np.random.randn(1)[0]  # Single number for all weights
        
        for w in weights:
            w_arr = np.array(w)
            
            # Push ALL weights in the SAME direction (extremely low entropy)
            # This creates a uniform update that will have entropy < 1.0
            w_mal = w_arr + global_direction * np.abs(w_arr) * 5.0  # Was 1.5, now 5.0
            
            malicious.append(w_mal.tolist())
        
        self.logger.warning(f"💥 Crafted UNIFORM directional updates (very low entropy, scale=5.0)")
        return malicious
    
    # ========== ADVERSARIAL/ROBUSTNESS ATTACKS (AGGRESSIVE) ==========
    
    def _attack_adversarial_examples(self, X):
        """
        AGGRESSIVE ADVERSARIAL_EXAMPLES: Add STRONG perturbations.
        """
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE ADVERSARIAL_EXAMPLES ATTACK")
        
        # Much larger epsilon
        epsilon = 1.0  # Was 0.1, now 1.0 (10x stronger)
        perturbations = np.random.uniform(-epsilon, epsilon, X.shape)
        X_adv = X + perturbations
        
        self.logger.warning(f"💥 Added STRONG adversarial perturbations (epsilon={epsilon})")
        return X_adv
    
    def _attack_model_drift(self, weights):
        """
        AGGRESSIVE MODEL_DRIFT: Cause SIGNIFICANT drift.
        """
        self.logger.warning(f"🔴 EXECUTING AGGRESSIVE MODEL_DRIFT ATTACK")
        
        # Much higher drift rate
        drift_rate = 0.5  # Was 0.05, now 0.5 (10x stronger)
        drifted = []
        
        for w in weights:
            w_arr = np.array(w)
            # Strong consistent directional drift
            drift = np.random.randn(*w_arr.shape) * np.std(w_arr) * drift_rate
            w_drift = w_arr + drift
            drifted.append(w_drift.tolist())
        
        self.logger.warning(f"💥 Applied STRONG model drift (rate={drift_rate})")
        return drifted
    
    def _attack_free_riding(self, weights):
        """
        FREE_RIDING: Submit essentially ZERO updates.
        """
        self.logger.warning(f"🔴 EXECUTING FREE_RIDING ATTACK")
        
        # Submit weights with TINY changes
        fake_updates = []
        for w in weights:
            w_arr = np.array(w)
            # Extremely tiny noise (should trigger free-riding detection)
            noise = np.random.normal(0, np.std(w_arr) * 0.00001, w_arr.shape)  # Was 0.01, now 0.00001
            fake_w = w_arr + noise
            fake_updates.append(fake_w.tolist())
        
        self.logger.warning(f"💥 Submitted MINIMAL fake updates (free-riding)")
        return fake_updates
    
    # ========== STEALTHY ATTACK (Combination) ==========
    
    def _attack_stealthy_data(self, X, y):
        """
        STEALTHY: Subtle combination attack.
        Less aggressive but still detectable.
        """
        self.logger.warning(f"🔴 EXECUTING STEALTHY ATTACK (subtle data corruption)")
        
        # Light noise
        noise_level = 0.2
        X_poisoned = X + np.random.normal(0, noise_level, X.shape)
        
        # Flip only 10% of labels
        flip_ratio = 0.1
        num_flip = int(len(y) * flip_ratio)
        flip_indices = np.random.choice(len(y), num_flip, replace=False)
        y_poisoned = y.copy()
        y_poisoned[flip_indices] = (y_poisoned[flip_indices] + 1) % 10
        
        self.logger.warning(f"🔶 Subtle corruption: {num_flip} samples ({flip_ratio*100}%)")
        return X_poisoned, y_poisoned
    
    # ========== PRIVACY ATTACKS ==========
    
    def _attack_gradient_inversion(self, weights):
        """GRADIENT_INVERSION: Analyze gradients to reconstruct training data"""
        self.logger.warning(f"🔴 EXECUTING GRADIENT_INVERSION ATTACK")
        
        if len(self.intercepted_gradients) > 1:
            prev_weights = self.intercepted_gradients[-2]['weights']
            curr_weights = weights
            
            gradient_diffs = []
            for prev_w, curr_w in zip(prev_weights, curr_weights):
                diff = np.array(curr_w) - np.array(prev_w)
                gradient_diffs.append(diff)
            
            self.attack_history.append({
                'attack': 'GRADIENT_INVERSION',
                'gradient_stats': {
                    'mean': float(np.mean([np.mean(g) for g in gradient_diffs])),
                    'std': float(np.std([np.std(g) for g in gradient_diffs]))
                }
            })
            self.logger.warning(f"📊 Analyzed gradients from {len(self.intercepted_gradients)} rounds")
        
        return weights
    
    def _attack_membership_inference(self, weights):
        """MEMBERSHIP_INFERENCE: Infer if data was in training"""
        self.logger.warning(f"🔴 EXECUTING MEMBERSHIP_INFERENCE ATTACK")
        
        X_test, y_test = self.training_data
        sample_indices = np.random.choice(len(X_test), min(10, len(X_test)), replace=False)
        
        predictions = self.model.predict(X_test[sample_indices], verbose=0)
        confidences = np.max(predictions, axis=1)
        
        self.attack_history.append({
            'attack': 'MEMBERSHIP_INFERENCE',
            'avg_confidence': float(np.mean(confidences)),
            'num_samples': len(sample_indices)
        })
        self.logger.warning(f"📊 Membership inference on {len(sample_indices)} samples")
        
        return weights
    
    def _attack_property_inference(self, weights):
        """PROPERTY_INFERENCE: Infer properties of other clients' data"""
        self.logger.warning(f"🔴 EXECUTING PROPERTY_INFERENCE ATTACK")
        
        weight_stats = []
        for w in weights:
            w_arr = np.array(w)
            weight_stats.append({
                'mean': float(np.mean(w_arr)),
                'std': float(np.std(w_arr)),
                'min': float(np.min(w_arr)),
                'max': float(np.max(w_arr))
            })
        
        self.attack_history.append({
            'attack': 'PROPERTY_INFERENCE',
            'weight_stats': weight_stats
        })
        self.logger.warning(f"📊 Inferred properties from weight distributions")
        
        return weights
    
    def submit_update(self, loss, accuracy):
        """Submit update with potential attacks"""
        weights = [w.tolist() for w in self.model.get_weights()]
        is_attack = False
        attack_type = 'NONE'
        
        # Apply attacks based on mode
        if self.attack_mode == 'MODEL_POISONING' or self.attack_mode == 'POISONING':
            weights = self._attack_model_poisoning(weights)
            is_attack = True
            attack_type = 'MODEL_POISONING'
        
        elif self.attack_mode == 'BACKDOOR':
            weights = self._attack_backdoor(weights)
            is_attack = True
            attack_type = 'BACKDOOR'
        
        elif self.attack_mode == 'MODEL_REPLACEMENT':
            weights = self._attack_model_replacement(weights)
            is_attack = True
            attack_type = 'MODEL_REPLACEMENT'
        
        elif self.attack_mode == 'MALICIOUS_AGGREGATION':
            weights = self._attack_malicious_aggregation(weights)
            is_attack = True
            attack_type = 'MALICIOUS_AGGREGATION'
        
        elif self.attack_mode == 'MODEL_DRIFT':
            weights = self._attack_model_drift(weights)
            is_attack = True
            attack_type = 'MODEL_DRIFT'
        
        elif self.attack_mode == 'FREE_RIDING':
            weights = self._attack_free_riding(weights)
            is_attack = True
            attack_type = 'FREE_RIDING'
        
        # Privacy attacks (don't modify weights but still mark as attack)
        elif self.attack_mode == 'GRADIENT_INVERSION':
            weights = self._attack_gradient_inversion(weights)
            is_attack = True
            attack_type = 'GRADIENT_INVERSION'
        
        elif self.attack_mode == 'MEMBERSHIP_INFERENCE':
            weights = self._attack_membership_inference(weights)
            is_attack = True
            attack_type = 'MEMBERSHIP_INFERENCE'
        
        elif self.attack_mode == 'PROPERTY_INFERENCE':
            weights = self._attack_property_inference(weights)
            is_attack = True
            attack_type = 'PROPERTY_INFERENCE'
        
        # Stealthy: combination attack
        elif self.attack_mode == 'STEALTHY':
            # Data corruption already done during training
            # Also do gradient inversion
            weights = self._attack_gradient_inversion(weights)
            is_attack = True
            attack_type = 'STEALTHY'
        
        # Data attacks already applied during training
        if self.attack_mode in ['DATA_POISONING', 'LABEL_FLIP', 'ADVERSARIAL_EXAMPLES']:
            is_attack = True
            attack_type = self.attack_mode
        
        try:
            payload_content = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat(),
                    'is_attack': is_attack,
                    'attack_type': attack_type
                },
            }
            
            # Sign payload
            payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
            signature = self.private_key.sign(payload_bytes)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            final_packet = {
                'payload': payload_content,
                'signature': signature_b64
            }
            
            response = requests.post(
                f'{self.server_url}/submit_update',
                json=final_packet
            )

            if response.status_code == 200:
                if is_attack:
                    self.logger.warning(f"💥 Attack update submitted ({attack_type})")
                else:
                    self.logger.info(f"✓ Update submitted")
                return True
            else:
                self.logger.warning(f"❌ Update rejected: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to submit: {e}")
            return False
    
    def run_training_cycle(self):
        """Complete training cycle"""
        self.logger.info(f"╔══ Starting training cycle ══╗")
        
        if not self.fetch_model():
            return False
        
        loss, accuracy = self.train_locally(epochs=2)
        
        if not self.submit_update(loss, accuracy):
            return False
        
        self.logger.info(f"╚══ Training cycle completed ══╝")
        return True
    
    def wait_for_server_signal(self, timeout=60):
        """Poll server for training signal"""
        try:
            self.logger.debug(f"Waiting for server signal (timeout={timeout}s)...")
            response = requests.post(
                f'{self.server_url}/wait_for_round',
                json={'client_id': self.client_id},
                timeout=timeout
            )
            self.logger.debug(f"Received response: {response.status_code}")
            if response.status_code == 200:
                self.logger.info(f"✓ Signal received from server")
                return True
            else:
                self.logger.warning(f"Unexpected status code: {response.status_code}")
                return False
        except requests.Timeout:
            self.logger.warning(f"⏱️ Timeout waiting for signal ({timeout}s)")
            return False
        except Exception as e:
            self.logger.error(f"❌ Error waiting for signal: {e}")
            return False

def main():
    client_id = os.getenv('CLIENT_ID', 'malicious_client')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'data/{client_id}_data.json')
    attack_mode = os.getenv('ATTACK_MODE', 'NONE')
    
    logger = logging.getLogger(f"CLIENT-{client_id}")
    
    # Wait for server
    logger.info("Waiting for server...")
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            logger.info("✓ Server ready")
            break
        except:
            logger.info(f"Waiting ({attempt + 1}/10)")
            time.sleep(2)
    
    client = MaliciousClient(client_id, server_url, data_file, attack_mode=attack_mode)
    
    logger.info("Entering main loop - waiting for training signals")
    consecutive_timeouts = 0
    while True:
        try:
            logger.debug(f"Polling for training signal...")
            if client.wait_for_server_signal(timeout=300):
                logger.info(f"🔔 Training signal received - starting training cycle")
                consecutive_timeouts = 0
                client.run_training_cycle()
            else:
                consecutive_timeouts += 1
                if consecutive_timeouts % 12 == 0:  # Log every hour (5s * 12 = 60s)
                    logger.info(f"Still waiting for training signal... ({consecutive_timeouts} polls)")
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Shutting down")
            break
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(5)

if __name__ == '__main__':
    main()