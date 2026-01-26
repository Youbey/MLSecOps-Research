"""
A compromised FL client that launches attacks during training.

Attack Modes:
1. POISONING - Large scaled update (Model Replacement)
2. STEALTHY - Constrain-and-scale (hide in normal magnitude)
3. SYBIL_SIMULATION - Correlated updates
4. GRADIENT_INVERSION - High-information gradients
5. NONE - Behave normally (for comparison)
"""

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
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"MALICIOUS-CLIENT")

class MaliciousClient:
    """
    A compromised FL client that performs attacks instead of honest training
    """
    
    def __init__(self, client_id: str, server_url: str, data_file: str, 
                 attack_mode: Literal['NONE', 'POISONING', 'STEALTHY', 'SYBIL_SIMULATION', 'GRADIENT_INVERSION'] = 'NONE',
                 attack_rounds: list = None):
        """
        Args:
            client_id: Unique client identifier
            server_url: FL server URL
            data_file: Path to training data
            attack_mode: Type of attack to perform
            attack_rounds: Which rounds to attack (e.g., [2, 3, 4])
        """
        self.client_id = client_id
        self.server_url = server_url
        self.attack_mode = attack_mode
        self.attack_rounds = attack_rounds or [2, 3, 4, 5]  # Start attacking from round 2
        self.current_round = 0
        
        # Setup logging with attack mode
        logger.name = f"MALICIOUS-{client_id}"
        logger.info(f" Initialized with attack mode: {attack_mode}")
        
        # Create model
        self.model = self._create_model()
        
        # Load data
        self.training_data = self._load_data(data_file)
        
        # Register with server
        self._register_with_server()
    
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
    
    def _load_data(self, data_file):
        """Load training data from file (Compatible with Medium Article N-Grams)"""
        with open(data_file, 'r') as f:
            data = json.json.load(f)
        
        # The data is now a list of sequences [word1, word2, word3, target]
        data_array = np.array(data)
        
        # Split into X (first 3 words) and y (last word)
        X = data_array[:, :-1]
        y = data_array[:, -1]
        
        logger.info(f"Loaded {len(X)} samples for client {self.client_id}")
        return X, y
    
    def _register_with_server(self):
        """Register with server"""
        try:
            response = requests.post(
                f'{self.server_url}/init_client',
                json={
                    'client_id': self.client_id,
                    'num_samples': len(self.training_data[0])
                }
            )
            logger.info(f" Registered with server: {response.json()}")
        except Exception as e:
            logger.error(f" Registration failed: {e}")
    
    def fetch_model(self):
        """Download global model from server"""
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            data = response.json()
            weights = [np.array(w) for w in data['weights']]
            self.model.set_weights(weights)
            self.current_round = data['round']
            logger.info(f" Fetched model from round {self.current_round}")
            return True
        except Exception as e:
            logger.error(f" Failed to fetch model: {e}")
            return False
    
    def train_locally(self, epochs=2):
        """Train model locally (honestly)"""
        logger.info(f" Training locally for {epochs} epochs")
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
        
        logger.info(f" Training complete: loss={loss:.4f}, accuracy={accuracy:.4f}")
        return loss, accuracy
    
    # ============================================
    # ATTACK IMPLEMENTATIONS
    # ============================================
    
    def _attack_poisoning(self, weights: np.ndarray) -> np.ndarray:
        """
        ATTACK 1: Model Replacement / Poisoning
        
        Scale weights by γ >> 1 to dominate aggregation
        γ = 100 means 100x larger than normal
        """
        logger.warning(f" ATTACKING: Model Replacement (Poisoning)")
        
        weights = np.array(weights, dtype=np.float32)
        gamma = 100.0  # Scaling factor - try to dominate aggregation
        
        # Scale all weights
        poisoned = weights * gamma
        
        logger.warning(f"   Scaled weights by γ={gamma}")
        logger.warning(f"   Original L2 norm: {np.linalg.norm(weights):.4f}")
        logger.warning(f"   Poisoned L2 norm: {np.linalg.norm(poisoned):.4f}")
        
        return poisoned.tolist()
    
    def _attack_stealthy(self, weights: np.ndarray) -> np.ndarray:
        """
        ATTACK 2: Constrain-and-Scale (Stealthy)
        
        Keep magnitude similar to benign but:
        - Reduce variance (tight distribution)
        - Embed backdoor in the pattern
        """
        logger.warning(f" ATTACKING: Constrain-and-Scale (Stealthy)")
        
        weights = np.array(weights, dtype=np.float32)
        
        # Keep the mean but drastically reduce variance
        mean = np.mean(weights)
        std = np.std(weights)
        
        # Create tightly constrained update
        constrained = np.random.normal(mean, std * 0.01, weights.shape)
        
        logger.warning(f"   Original std: {std:.4f}")
        logger.warning(f"   Constrained std: {np.std(constrained):.4f}")
        logger.warning(f"   Looks benign but is stealthy!")
        
        return constrained.tolist()
    
    def _attack_sybil_simulation(self, weights: np.ndarray) -> np.ndarray:
        """
        ATTACK 3: Sybil Simulation
        
        This client submits as if it's multiple clients
        (In real scenario, would control multiple client IDs)
        
        Here we just produce highly correlated updates
        """
        logger.warning(f" ATTACKING: Sybil Simulation (Correlated)")
        
        weights = np.array(weights, dtype=np.float32)
        
        # Add tiny noise to base attack (like multiple Sybils)
        base_attack = np.random.normal(5.0, 0.5, weights.shape)
        sybil_version = base_attack + np.random.normal(0, 0.01, weights.shape)
        
        logger.warning(f"   Creating highly correlated update")
        logger.warning(f"   L2 norm: {np.linalg.norm(sybil_version):.4f}")
        
        return sybil_version.tolist()
    
    def _attack_gradient_inversion(self, weights: np.ndarray) -> np.ndarray:
        """
        ATTACK 4: Gradient Inversion (Privacy Attack)
        
        Submit large, information-rich gradients
        that expose training data to inversion attacks
        """
        logger.warning(f" ATTACKING: Gradient Inversion (Privacy Attack)")
        
        weights = np.array(weights, dtype=np.float32)
        
        # Amplify to maximize information content
        info_rich = weights * 20.0
        
        logger.warning(f"   Amplifying gradients to maximize information")
        logger.warning(f"   L2 norm: {np.linalg.norm(info_rich):.4f}")
        logger.warning(f"   This exposes training data to DLG attack!")
        
        return info_rich.tolist()
    
    def should_attack(self) -> bool:
        """Check if should attack this round"""
        should = self.current_round in self.attack_rounds
        
        if should:
            logger.warning(f" ATTACK ROUND DETECTED: Round {self.current_round} is in attack_rounds")
        
        return should
    
    def submit_update(self, weights: np.ndarray, loss: float, accuracy: float):
        """Submit update (potentially poisoned)"""
        
        # Check if should attack
        if self.attack_mode != 'NONE' and self.should_attack():
            logger.warning(f"\n{'='*70}")
            logger.warning(f"LAUNCHING ATTACK IN ROUND {self.current_round}")
            logger.warning(f"Attack Mode: {self.attack_mode}")
            logger.warning(f"{'='*70}\n")
            
            # Apply attack
            if self.attack_mode == 'POISONING':
                weights = self._attack_poisoning(weights)
            elif self.attack_mode == 'STEALTHY':
                weights = self._attack_stealthy(weights)
            elif self.attack_mode == 'SYBIL_SIMULATION':
                weights = self._attack_sybil_simulation(weights)
            elif self.attack_mode == 'GRADIENT_INVERSION':
                weights = self._attack_gradient_inversion(weights)
            
            # Submit poisoned update
            payload = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat(),
                    'is_poisoned': True,  # Mark as poisoned
                    'attack_type': self.attack_mode
                }
            }
        else:
            # Submit honest update
            weights_list = [w.tolist() for w in self.model.get_weights()]
            
            payload = {
                'client_id': self.client_id,
                'weights': weights_list,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat(),
                    'is_poisoned': False,
                    'attack_type': 'NONE'
                }
            }
        
        # Send to server
        try:
            response = requests.post(
                f'{self.server_url}/submit_update',
                json=payload
            )
            
            size_bytes = len(json.dumps(payload))
            logger.info(f" Update submitted: {size_bytes} bytes")
            
            return True
        except Exception as e:
            logger.error(f" Failed to submit update: {e}")
            return False
    
    def run_training_cycle(self):
        """Run one FL cycle with potential attack"""
        
        logger.info(f"\n{'='*70}")
        logger.info(f"Training Cycle (Round {self.current_round})")
        logger.info(f"{'='*70}")
        
        # Fetch model
        if not self.fetch_model():
            return False
        
        # Train locally
        loss, accuracy = self.train_locally(epochs=2)
        
        # Get weights
        weights = np.array(self.model.get_weights(), dtype=object)
        
        # Submit (may be poisoned)
        if not self.submit_update(weights, loss, accuracy):
            return False
        
        logger.info(f" Cycle complete\n")
        return True


def main():
    """Main entry point"""
    
    # Get configuration from environment
    client_id = os.getenv('CLIENT_ID', 'malicious_client')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'/data/{client_id}_data.json')
    attack_mode = os.getenv('ATTACK_MODE', 'NONE')  # NONE, POISONING, STEALTHY, SYBIL_SIMULATION, GRADIENT_INVERSION
    
    logger.info(f" Starting MALICIOUS CLIENT: {client_id}")
    logger.info(f"   Attack Mode: {attack_mode}")
    logger.info(f"   Server: {server_url}")
    
    # Wait for server
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            break
        except:
            logger.info(f"   Waiting for server... ({attempt + 1}/10)")
            time.sleep(2)
    
    # Create malicious client
    client = MaliciousClient(
        client_id=client_id,
        server_url=server_url,
        data_file=data_file,
        attack_mode=attack_mode,
        attack_rounds=[2, 3, 4, 5]  # Attack in rounds 2-5
    )
    
    # Run continuous training cycles
    cycle = 0
    while True:
        cycle += 1
        logger.info(f"\n>>> Cycle {cycle}")
        client.run_training_cycle()
        
        # Wait before next cycle
        time.sleep(5)


if __name__ == '__main__':
    main()