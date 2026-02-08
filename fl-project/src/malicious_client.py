import os
import sys
import json
import numpy as np
import tensorflow as tf
import requests
import time
import logging
from datetime import datetime
from typing import Literal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class MaliciousClient:
    def __init__(self, client_id, server_url, data_file, attack_mode='NONE', attack_rounds=None):
        self.client_id = client_id
        self.server_url = server_url
        self.attack_mode = attack_mode
        self.attack_rounds = attack_rounds or [2, 3, 4, 5]
        self.current_round = 0
        
        self.logger = logging.getLogger(f"CLIENT-{client_id}")
        
        # Create model structure (with random initial weights)
        self.model = self._create_model()
        
        # Load training data
        self.training_data = self._load_data(data_file)
        
        self.logger.info(f"Initialized client (attack_mode={attack_mode})")
        
        # Register with server and receive initial model weights
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
            response = requests.post(
                f'{self.server_url}/init_client',
                json={
                    'client_id': self.client_id,
                    'num_samples': len(self.training_data[0])
                }
            )
            
            data = response.json()
            
            # CRITICAL: Set initial weights from server
            if 'initial_weights' in data:
                weights = [np.array(w) for w in data['initial_weights']]
                self.model.set_weights(weights)
                self.current_round = data['round']
                self.logger.info(f"Registered with server and received initial model (round {self.current_round})")
                self.logger.info(f"Model synchronized with server's global model")
            else:
                self.logger.warning("No initial weights received from server!")
                self.logger.warning("Model may not be synchronized!")
                
        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
    
    def fetch_model(self):
        """Fetch the latest global model from server before training"""
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            data = response.json()
            weights = [np.array(w) for w in data['weights']]
            self.model.set_weights(weights)
            self.current_round = data['round']
            self.logger.info(f"✓ Fetched latest global model from server (round {self.current_round})")
            return True
        except Exception as e:
            self.logger.error(f"Failed to fetch model: {e}")
            return False
    
    def train_locally(self, epochs=2):
        self.logger.info(f"Starting local training ({epochs} epochs)")
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
        
        self.logger.info(f"Training completed - loss={loss:.4f}, accuracy={accuracy:.4f}")
        return loss, accuracy
    
    def _should_attack(self):
        return True
    
    def _attack_poisoning(self, weights):
        """Scale weights massively to dominate aggregation"""
        self.logger.warning(f"EXECUTING POISONING ATTACK - Round {self.current_round}")
        
        gamma = 100.0
        # 1. Multiply the weights
        # 2. Convert back to list using .tolist() so JSON can read it
        poisoned = [(np.array(w) * gamma).tolist() for w in weights]
        
        self.logger.warning(f"Scaled weights by gamma={gamma}")
        return poisoned

    def _attack_stealthy(self, weights):
        """Constrain-and-scale - hide attack in normal magnitude but still detectable"""
        self.logger.warning(f"EXECUTING STEALTHY ATTACK - Round {self.current_round}")
        
        # More aggressive 
        constrained = []
        for w in weights:
            w_arr = np.array(w)
            mean = np.mean(w_arr)
            std = np.std(w_arr)
            # Scale by 1.5 and add controlled noise
            perturbed = w_arr * 1.5 + np.random.normal(0, std * 0.1, w_arr.shape)
            constrained.append(perturbed.tolist())
        
        self.logger.warning(f"Applied stealthy perturbation (1.5x scale + noise)")
        return constrained
  
    def _attack_sybil(self, weights):
        """Create correlated updates simulating multiple clients"""
        self.logger.warning(f"EXECUTING SYBIL ATTACK - Round {self.current_round}")
        
        # Create weights that deviate from global model
        base = []
        for w in weights:
            w_arr = np.array(w)
            # Create significantly different weights to simulate multiple malicious clients
            # Use 3x scaling to make it detectable
            perturbed = w_arr * 3.0 + np.random.normal(0, 1.0, w_arr.shape)
            base.append(perturbed.tolist())
        
        self.logger.warning(f"Created sybil simulation (3x scale)")
        return base
    
    def _attack_gradient_inversion(self, weights):
        """Amplify gradients to expose training data"""
        self.logger.warning(f"EXECUTING GRADIENT INVERSION ATTACK - Round {self.current_round}")
        
        # Amplify each weight array
        amplified = []
        for w in weights:
            w_arr = np.array(w)
            # Amplify by 20x and convert to list
            amplified.append((w_arr * 20.0).tolist())
        
        self.logger.warning(f"Amplified gradients by 20x for DLG attack")
        return amplified
    
    def submit_update(self, loss, accuracy):
        weights = [w.tolist() for w in self.model.get_weights()]
        
        # Check if should attack
        if self.attack_mode != 'NONE' and self._should_attack():
            self.logger.warning(f"🔴 ATTACK TRIGGERED IN ROUND {self.current_round}")
            
            if self.attack_mode == 'POISONING':
                weights = self._attack_poisoning(weights)
            elif self.attack_mode == 'STEALTHY':
                weights = self._attack_stealthy(weights)
            elif self.attack_mode == 'SYBIL':
                weights = self._attack_sybil(weights)
            elif self.attack_mode == 'GRADIENT_INVERSION':
                weights = self._attack_gradient_inversion(weights)
            
            is_poisoned = True
        else:
            is_poisoned = False
        
        try:
            payload = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat(),
                    'is_poisoned': is_poisoned,
                    'attack_type': self.attack_mode if is_poisoned else 'NONE'
                }
            }
            
            response = requests.post(
                f'{self.server_url}/submit_update',
                json=payload
            )

            if response.status_code == 200:
                if is_poisoned:
                    self.logger.warning(f"Poisoned update submitted successfully")
                else:
                    self.logger.info(f"Update submitted successfully")
                return True
            else:
                self.logger.warning(f"Update rejected: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to submit update: {e}")
            return False
    
    def run_training_cycle(self):
        """
        Complete training cycle:
        1. Fetch latest global model from server
        2. Train locally (potentially with poisoned data)
        3. Submit weight updates (potentially poisoned)
        """
        self.logger.info(f"═══ Starting training cycle ═══")
        
        # STEP 1: Fetch latest global model
        self.logger.info(f"[1/3] Fetching latest global model...")
        if not self.fetch_model():
            self.logger.error(f"Failed to fetch model, aborting cycle")
            return False
        
        # STEP 2: Train locally
        self.logger.info(f"[2/3] Training locally...")
        loss, accuracy = self.train_locally(epochs=2)
        
        # STEP 3: Submit update (may be poisoned)
        self.logger.info(f"[3/3] Submitting update to server...")
        if not self.submit_update(loss, accuracy):
            self.logger.error(f"Failed to submit update")
            return False
        
        self.logger.info(f"═══ Training cycle completed ═══")
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
            self.logger.error(f"Error waiting for signal: {e}")
            return False
        return False

def main():
    client_id = os.getenv('CLIENT_ID', 'malicious_client')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'data/{client_id}_data.json')
    attack_mode = os.getenv('ATTACK_MODE', 'NONE')
    
    logger = logging.getLogger(f"CLIENT-{client_id}")
    
    # Wait for server to start
    logger.info("Waiting for server to be ready...")
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            logger.info("Server is ready")
            break
        except:
            logger.info(f"Waiting for server ({attempt + 1}/10)")
            time.sleep(2)
    
    # Initialize client (this will sync with server's initial model)
    client = MaliciousClient(client_id, server_url, data_file, attack_mode=attack_mode)
    
    # Main loop: wait for signal, train (potentially with attack), repeat
    logger.info("Entering main loop - waiting for training signals")
    while True:
        try:
            if client.wait_for_server_signal(timeout=300):
                logger.info(f"🔔 Received training signal from server")
                client.run_training_cycle()
            else:
                logger.debug("No training signal received, waiting...")
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Client shutting down")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()