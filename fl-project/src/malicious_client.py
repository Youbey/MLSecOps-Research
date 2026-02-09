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

class maliciousClient:
    """
     malicious client implementing all attack types from FL taxonomy:
    
    INTEGRITY ATTACKS:
    - DATA_POISONING: Corrupt training data
    - MODEL_POISONING: Manipulate model updates (Byzantine)
    - BACKDOOR: Inject backdoor trigger patterns
    - LABEL_FLIP: Flip training labels
    
    PRIVACY ATTACKS:
    - GRADIENT_INVERSION: Reconstruct training data from gradients
    - MEMBERSHIP_INFERENCE: Infer if data was in training set
    - PROPERTY_INFERENCE: Infer dataset properties
    
    AGGREGATOR/SERVER ATTACKS (simulated from client side):
    - MODEL_REPLACEMENT: Replace entire model with adversarial version
    - MALICIOUS_AGGREGATION: Craft updates to exploit aggregation
    
    ADVERSARIAL/ROBUSTNESS ATTACKS:
    - ADVERSARIAL_EXAMPLES: Add adversarial perturbations
    - MODEL_DRIFT: Cause model to drift from global objective
    - FREE_RIDING: Submit minimal/fake updates while benefiting
    """
    
    def __init__(self, client_id, server_url, data_file, attack_mode='NONE'):
        self.client_id = client_id
        self.server_url = server_url
        self.attack_mode = attack_mode
        self.current_round = 0
        
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
        
        self.logger.info(f"Initialized  malicious client (attack_mode={attack_mode})")
        
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
                self.current_round = data['round']
                self.logger.info(f"Registered (round {self.current_round})")
                
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
                    self.current_round = payload_content['round']
                except Exception as e:
                    self.logger.critical(f"🔴 Server signature INVALID! {e}")
                    return False
            else:
                weights = [np.array(w) for w in data['weights']]
                self.current_round = data['round']
            
            self.model.set_weights(weights)
            
            # Store for privacy attacks
            if self.attack_mode in ['GRADIENT_INVERSION', 'MEMBERSHIP_INFERENCE', 'PROPERTY_INFERENCE']:
                self.intercepted_gradients.append({
                    'round': self.current_round,
                    'weights': weights
                })
            
            self.logger.info(f"✓ Fetched model (round {self.current_round})")
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
        
        # DATA_POISONING: Use corrupted data
        if self.attack_mode == 'DATA_POISONING':
            X, y = self._attack_data_poisoning(X, y)
        
        # LABEL_FLIP: Flip labels
        elif self.attack_mode == 'LABEL_FLIP':
            y = self._attack_label_flip(y)
        
        # ADVERSARIAL_EXAMPLES: Add adversarial perturbations to training data
        elif self.attack_mode == 'ADVERSARIAL_EXAMPLES':
            X = self._attack_adversarial_examples(X)
        
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
    
    # ========== INTEGRITY ATTACKS ==========
    
    def _attack_data_poisoning(self, X, y):
        """
        DATA_POISONING: Corrupt training data by adding noise or wrong samples.
        Different from label flip - corrupts features too.
        """
        self.logger.warning(f"EXECUTING DATA_POISONING ATTACK - Round {self.current_round}")
        
        # Add noise to features
        noise_level = 0.3
        X_poisoned = X + np.random.normal(0, noise_level, X.shape)
        
        # Also flip some labels
        flip_ratio = 0.2
        num_flip = int(len(y) * flip_ratio)
        flip_indices = np.random.choice(len(y), num_flip, replace=False)
        y_poisoned = y.copy()
        y_poisoned[flip_indices] = np.random.randint(0, 10, num_flip)
        
        self.logger.warning(f"Corrupted {num_flip} samples with noise and label flips")
        return X_poisoned, y_poisoned
    
    def _attack_label_flip(self, labels):
        """LABEL_FLIP: Systematically flip labels"""
        num_classes = int(np.max(labels)) + 1
        flipped = (labels + 1) % num_classes
        self.logger.warning(f"Flipped {len(labels)} labels")
        return flipped
    
    def _attack_model_poisoning(self, weights):
        """MODEL_POISONING: Byzantine attack - scale weights massively"""
        self.logger.warning(f"EXECUTING MODEL_POISONING ATTACK - Round {self.current_round}")
        gamma = 100.0
        poisoned = [(np.array(w) * gamma).tolist() for w in weights]
        self.logger.warning(f"Scaled weights by gamma={gamma}")
        return poisoned
    
    def _attack_backdoor(self, weights):
        """BACKDOOR: Inject trigger pattern"""
        self.logger.warning(f"EXECUTING BACKDOOR ATTACK - Round {self.current_round}")
        
        backdoored = []
        for i, w in enumerate(weights):
            w_arr = np.array(w)
            if i == len(weights) - 1:  # Output layer
                trigger_pattern = np.random.uniform(-0.1, 0.1, w_arr.shape)
                w_backdoor = w_arr + trigger_pattern * 2.0
            else:
                w_backdoor = w_arr
            backdoored.append(w_backdoor.tolist())
        
        self.logger.warning(f"Injected backdoor trigger")
        return backdoored
    
    # ========== AGGREGATOR/SERVER ATTACKS ==========
    
    def _attack_model_replacement(self, weights):
        """
        MODEL_REPLACEMENT: Replace entire model with adversarial version.
        Create a model trained on adversarial objective.
        """
        self.logger.warning(f"EXECUTING MODEL_REPLACEMENT ATTACK - Round {self.current_round}")
        
        # Train a model on adversarial objective (e.g., maximize loss)
        adversarial_model = self._create_model()
        X, y = self.original_data
        
        # Flip all labels for adversarial training
        y_adv = (y + 5) % 10  # Shift labels
        
        adversarial_model.fit(X, y_adv, epochs=1, batch_size=8, verbose=0)
        
        # Replace with adversarial weights
        adv_weights = [w.tolist() for w in adversarial_model.get_weights()]
        
        # Scale to dominate aggregation
        scale_factor = 10.0
        replaced = [(np.array(w) * scale_factor).tolist() for w in adv_weights]
        
        self.logger.warning(f"Replaced model with adversarial version (scaled by {scale_factor})")
        return replaced
    
    def _attack_malicious_aggregation(self, weights):
        """
        MALICIOUS_AGGREGATION: Craft updates to exploit aggregation algorithm.
        Use knowledge of FedAvg to maximize impact.
        """
        self.logger.warning(f"EXECUTING MALICIOUS_AGGREGATION ATTACK - Round {self.current_round}")
        
        # Strategy: Create updates that amplify in specific directions
        # while staying within detection bounds
        malicious = []
        for w in weights:
            w_arr = np.array(w)
            
            # Add directional bias
            direction = np.random.randn(*w_arr.shape)
            direction = direction / (np.linalg.norm(direction) + 1e-8)
            
            # Scale carefully to evade detection
            scale = 1.5  # Just above normal variation
            w_mal = w_arr + direction * np.std(w_arr) * scale
            
            malicious.append(w_mal.tolist())
        
        self.logger.warning(f"Crafted updates to exploit aggregation (scale={scale})")
        return malicious
    
    # ========== ADVERSARIAL/ROBUSTNESS ATTACKS ==========
    
    def _attack_adversarial_examples(self, X):
        """
        ADVERSARIAL_EXAMPLES: Add adversarial perturbations to training data.
        Use FGSM-like approach.
        """
        self.logger.warning(f"EXECUTING ADVERSARIAL_EXAMPLES ATTACK - Round {self.current_round}")
        
        # Add small adversarial perturbations
        epsilon = 0.1
        perturbations = np.random.uniform(-epsilon, epsilon, X.shape)
        X_adv = X + perturbations
        
        self.logger.warning(f"Added adversarial perturbations (epsilon={epsilon})")
        return X_adv
    
    def _attack_model_drift(self, weights):
        """
        MODEL_DRIFT: Cause gradual drift from global objective.
        Submit updates that slowly push model in wrong direction.
        """
        self.logger.warning(f"EXECUTING MODEL_DRIFT ATTACK - Round {self.current_round}")
        
        # Add small consistent bias to cause drift
        drift_rate = 0.05
        drifted = []
        
        for w in weights:
            w_arr = np.array(w)
            # Add consistent directional drift
            drift = np.random.randn(*w_arr.shape) * np.std(w_arr) * drift_rate
            w_drift = w_arr + drift
            drifted.append(w_drift.tolist())
        
        self.logger.warning(f"Applied model drift (rate={drift_rate})")
        return drifted
    
    def _attack_free_riding(self, weights):
        """
        FREE_RIDING: Submit fake/minimal updates without actual training.
        Benefit from global model without contributing.
        """
        self.logger.warning(f"EXECUTING FREE_RIDING ATTACK - Round {self.current_round}")
        
        # Submit weights with minimal changes (random noise)
        fake_updates = []
        for w in weights:
            w_arr = np.array(w)
            # Add tiny random noise to appear legitimate
            noise = np.random.normal(0, np.std(w_arr) * 0.01, w_arr.shape)
            fake_w = w_arr + noise
            fake_updates.append(fake_w.tolist())
        
        self.logger.warning(f"Submitted fake updates (free-riding)")
        return fake_updates
    
    # ========== PRIVACY ATTACKS ==========
    
    def _attack_gradient_inversion(self, weights):
        """GRADIENT_INVERSION: Analyze gradients to reconstruct training data"""
        self.logger.warning(f"EXECUTING GRADIENT_INVERSION ATTACK - Round {self.current_round}")
        
        if len(self.intercepted_gradients) > 1:
            prev_weights = self.intercepted_gradients[-2]['weights']
            curr_weights = weights
            
            gradient_diffs = []
            for prev_w, curr_w in zip(prev_weights, curr_weights):
                diff = np.array(curr_w) - np.array(prev_w)
                gradient_diffs.append(diff)
            
            self.attack_history.append({
                'round': self.current_round,
                'attack': 'GRADIENT_INVERSION',
                'gradient_stats': {
                    'mean': float(np.mean([np.mean(g) for g in gradient_diffs])),
                    'std': float(np.std([np.std(g) for g in gradient_diffs]))
                }
            })
            self.logger.warning(f"Analyzed gradients from {len(self.intercepted_gradients)} rounds")
        
        return weights
    
    def _attack_membership_inference(self, weights):
        """MEMBERSHIP_INFERENCE: Infer if data was in training"""
        self.logger.warning(f"EXECUTING MEMBERSHIP_INFERENCE ATTACK - Round {self.current_round}")
        
        X_test, y_test = self.training_data
        sample_indices = np.random.choice(len(X_test), min(10, len(X_test)), replace=False)
        
        predictions = self.model.predict(X_test[sample_indices], verbose=0)
        confidences = np.max(predictions, axis=1)
        
        self.attack_history.append({
            'round': self.current_round,
            'attack': 'MEMBERSHIP_INFERENCE',
            'avg_confidence': float(np.mean(confidences)),
            'num_samples': len(sample_indices)
        })
        self.logger.warning(f"Membership inference on {len(sample_indices)} samples")
        
        return weights
    
    def _attack_property_inference(self, weights):
        """PROPERTY_INFERENCE: Infer properties of other clients' data"""
        self.logger.warning(f"EXECUTING PROPERTY_INFERENCE ATTACK - Round {self.current_round}")
        
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
            'round': self.current_round,
            'attack': 'PROPERTY_INFERENCE',
            'weight_stats': weight_stats
        })
        self.logger.warning(f"Inferred properties from weight distributions")
        
        return weights
    
    def submit_update(self, loss, accuracy):
        """Submit update with potential attacks"""
        weights = [w.tolist() for w in self.model.get_weights()]
        is_attack = False
        attack_type = 'NONE'
        
        # Apply attacks based on mode
        if self.attack_mode == 'MODEL_POISONING':
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
        
        # Privacy attacks (don't modify weights)
        elif self.attack_mode == 'GRADIENT_INVERSION':
            self._attack_gradient_inversion(weights)
            attack_type = 'GRADIENT_INVERSION'
        
        elif self.attack_mode == 'MEMBERSHIP_INFERENCE':
            self._attack_membership_inference(weights)
            attack_type = 'MEMBERSHIP_INFERENCE'
        
        elif self.attack_mode == 'PROPERTY_INFERENCE':
            self._attack_property_inference(weights)
            attack_type = 'PROPERTY_INFERENCE'
        
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
                'round': self.current_round
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
                    self.logger.warning(f"Attack update submitted")
                else:
                    self.logger.info(f"Update submitted")
                return True
            else:
                self.logger.warning(f"Update rejected: {response.text}")
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
            response = requests.post(
                f'{self.server_url}/wait_for_round',
                json={'client_id': self.client_id},
                timeout=timeout
            )
            if response.status_code == 200:
                return True
        except requests.Timeout:
            return False
        except Exception as e:
            self.logger.error(f"Error waiting: {e}")
            return False
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
            logger.info("Server ready")
            break
        except:
            logger.info(f"Waiting ({attempt + 1}/10)")
            time.sleep(2)
    
    client = maliciousClient(client_id, server_url, data_file, attack_mode=attack_mode)
    
    logger.info("Entering main loop")
    while True:
        try:
            if client.wait_for_server_signal(timeout=300):
                logger.info(f"🔔 Training signal received")
                client.run_training_cycle()
            else:
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Shutting down")
            break
        except Exception as e:
            logger.error(f"Error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()