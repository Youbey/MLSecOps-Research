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
import base64
import base64
from datetime import datetime
from typing import Literal
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"MALICIOUS-CLIENT")

try:
    from structured_logger import logger as structured_logger
except ImportError:
    structured_logger = None

class MaliciousClient:
    """
    A compromised FL client that performs attacks instead of honest training.
    It MUST implement the security protocol (keys/tokens) to be accepted by the server.
    """

    def __init__(self, client_id: str, server_url: str, data_file: str,
                 attack_mode: Literal['NONE', 'POISONING', 'STEALTHY', 'SYBIL_SIMULATION', 'GRADIENT_INVERSION'] = 'NONE',
                 attack_rounds: list = None):

        self.client_id = client_id
        self.server_url = server_url
        self.attack_mode = attack_mode
        self.attack_rounds = attack_rounds or [2, 3, 4, 5]
        self.current_round = 0
        self.registration_token = os.getenv('REGISTRATION_TOKEN')

        # SECURITY: Generate Keys to impersonate a valid client
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Setup logging
        logger.name = f"MALICIOUS-{client_id}"
        logger.info(f" Initialized with attack mode: {attack_mode}")

        self.model = self._create_model()
        self.training_data = self._load_data(data_file)

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
        try:
            with open(data_file, 'r') as f:
                data = json.load(f)
            # The data is now a list of sequences [word1, word2, word3, target]
            data_array = np.array(data)
            # Split into X (first 3 words) and y (last word)
            X = data_array[:, :-1]
            y = data_array[:, -1]
            return X, y
        except Exception as e:
            logger.error(f"Failed to load data: {e}")
            sys.exit(1)

    def _register_with_server(self):
        """Register securely with Public Key + Token"""
        try:
            # Serialize Public Key
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            payload = {
                'client_id': self.client_id,
                'num_samples': len(self.training_data[0]),
                'public_key': pem,
                'token': self.registration_token
            }

            response = requests.post(f'{self.server_url}/init_client', json=payload)
            if response.status_code == 200:
                logger.info(f" Successfully Registered (Secure): {response.json()}")
            else:
                logger.error(f" Registration Failed: {response.text}")
                sys.exit(1)
        except Exception as e:
            logger.error(f" Connection error during registration: {e}")
            sys.exit(1)

    def fetch_model(self):
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            if response.status_code != 200:
                logger.error(f"Fetch failed: {response.text}")
                return False

            data = response.json()

            # Verify Signature logic same as client.py
            if self.server_public_key and 'signature' in data:
                try:
                    payload_content = data['payload']
                    signature = base64.b64decode(data['signature'])
                    payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
                    self.server_public_key.verify(signature, payload_bytes)
                except Exception as e:
                    logger.warning(f"Server signature invalid: {e}")
                    # Malicious client might ignore this validation to keep attacking

            model_data = data['payload']
            weights = [np.array(w) for w in model_data['weights']]
            self.model.set_weights(weights)
            self.current_round = model_data['round']
            return True
        except Exception:
            return False


    def train_locally(self, epochs=2):
        logger.info(f" Training locally for {epochs} epochs")
        X, y = self.training_data
        history = self.model.fit(X, y, epochs=epochs, batch_size=8, verbose=0, validation_split=0.2)
        return float(history.history['loss'][-1]), float(history.history['accuracy'][-1])

    # --- ATTACK LOGIC (UNCHANGED) ---
    def _attack_poisoning(self, weights: np.ndarray) -> np.ndarray:
        logger.warning(f" ATTACKING: Model Replacement (Poisoning)")
        # Cast to float32 to avoid serialization issues
        weights = np.array(weights, dtype=np.float32)
        return (weights * 100.0).tolist()

    def _attack_stealthy(self, weights: np.ndarray) -> np.ndarray:
        logger.warning(f" ATTACKING: Constrain-and-Scale (Stealthy)")
        arr = np.array(weights, dtype=np.float32)
        mean = np.mean(arr)
        std = np.std(arr)
        return np.random.normal(mean, std * 0.01, arr.shape).tolist()

    def _attack_sybil_simulation(self, weights: np.ndarray) -> np.ndarray:
        logger.warning(f" ATTACKING: Sybil Simulation")
        arr = np.array(weights, dtype=np.float32)
        base = np.random.normal(5.0, 0.5, arr.shape)
        return (base + np.random.normal(0, 0.01, arr.shape)).tolist()

    def _attack_gradient_inversion(self, weights: np.ndarray) -> np.ndarray:
        logger.warning(f" ATTACKING: Gradient Inversion")
        arr = np.array(weights, dtype=np.float32)
        return (arr * 20.0).tolist()

    def should_attack(self) -> bool:
        return self.current_round in self.attack_rounds

    def submit_update(self, weights: np.ndarray, loss: float, accuracy: float):
        """Submit signed update (potentially poisoned)"""

        # 1. Prepare Payload Content
        payload_content = {
            'client_id': self.client_id,
            'metrics': {
                'loss': loss,
                'accuracy': accuracy,
                'timestamp': datetime.now().isoformat(),
                'attack_type': 'NONE',
                'is_poisoned': False
            },
            'round': self.current_round
        }

        # Apply Attack if needed
        final_weights = weights # Default to honest weights

        if self.attack_mode != 'NONE' and self.should_attack():
            logger.warning(f" LAUNCHING ATTACK: {self.attack_mode}")

            # Apply transformation
            if self.attack_mode == 'POISONING':
                final_weights = self._attack_poisoning(weights)
            elif self.attack_mode == 'STEALTHY':
                final_weights = self._attack_stealthy(weights)
            elif self.attack_mode == 'SYBIL_SIMULATION':
                final_weights = self._attack_sybil_simulation(weights)
            elif self.attack_mode == 'GRADIENT_INVERSION':
                final_weights = self._attack_gradient_inversion(weights)
            else:
                # Fallback for safe types
                final_weights = [w.tolist() for w in weights]

            # Update metadata
            payload_content['metrics']['is_poisoned'] = True
            payload_content['metrics']['attack_type'] = self.attack_mode

            if structured_logger:
                structured_logger.log_attack_detected(
                    attack_type=self.attack_mode,
                    client_id=self.client_id,
                    confidence=0.95,
                    round_number=self.current_round
                )
        else:
            # Honest update formatting
            final_weights = [w.tolist() for w in weights]

        # Add weights to content
        payload_content['weights'] = final_weights

        # 2. SIGN THE PAYLOAD (Crucial Step for Authentication)
        try:
            # Canonical JSON serialization for signing
            payload_bytes = json.dumps(payload_content, sort_keys=True).encode()

            # Sign with private key
            signature = self.private_key.sign(payload_bytes)
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # 3. Create Final Packet
            final_packet = {
                'payload': payload_content,
                'signature': signature_b64
            }

            # Send
            response = requests.post(f'{self.server_url}/submit_update', json=final_packet)

            size_bytes = len(json.dumps(final_packet))
            if response.status_code == 200:
                logger.info(f" Update submitted successfully ({size_bytes} bytes)")
                return True
            else:
                logger.error(f" Update REJECTED by server: {response.text}")
                return False

        except Exception as e:
            logger.error(f" Failed to sign/submit update: {e}")
            return False


    def run_training_cycle(self):
        logger.info(f"\n{'='*70}\nTraining Cycle (Round {self.current_round})\n{'='*70}")
        if not self.fetch_model(): return False
        loss, accuracy = self.train_locally(epochs=2)
        weights = self.model.get_weights() # Keep as numpy arrays list initially
        if not self.submit_update(weights, loss, accuracy): return False
        logger.info(f" Cycle complete\n")
        return True

def main():
    client_id = os.getenv('CLIENT_ID', 'malicious_client')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'/data/{client_id}_data.json')
    attack_mode = os.getenv('ATTACK_MODE', 'NONE')

    logger.info(f" Starting MALICIOUS CLIENT: {client_id} (Mode: {attack_mode})")

    # Wait for server
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            logger.info("Server is up!")
            break
        except:
            time.sleep(2)

    client = MaliciousClient(
        client_id=client_id,
        server_url=server_url,
        data_file=data_file,
        attack_mode=attack_mode
    )

    # Run loop
    last_processed_round = -1
    while True:
        try:
            response = requests.get(f'{server_url}/health', timeout=5)
            server_round = response.json().get('round', 0)

            if server_round > last_processed_round:
                client.current_round = server_round
                if client.run_training_cycle():
                    last_processed_round = server_round
                else:
                    time.sleep(5)
            else:
                time.sleep(2)
        except Exception as e:
            logger.error(f"Connection error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()