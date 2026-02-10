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
    def __init__(self, client_id, server_url, data_file, attack_mode='NONE', attack_rounds=None):
        self.client_id = client_id
        self.server_url = server_url
        self.attack_mode = attack_mode
        self.attack_rounds = attack_rounds or [2, 3, 4, 5]
        self.current_round = 0

        self.logger = logging.getLogger(f"CLIENT-{client_id}")

        # Security - Registration token and cryptographic keys
        self.registration_token = os.getenv('REGISTRATION_TOKEN')
        self.server_public_key = None
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # SYBIL: Store fake identities
        self.sybils = []

        # Create model structure (with random initial weights)
        self.model = self._create_model()

        # Load training data
        self.training_data = self._load_data(data_file)

        # Register main identity
        self._register_identity(self.client_id, self.public_key)

        self.logger.info(f"Initialized client (attack_mode={attack_mode})")

        # Register with server and receive initial model weights
        # Removed for sybil attack
        #self._register_with_server()

        # If Sybil attack, setup fake identities
        if self.attack_mode == 'SYBIL_SIMULATION':
            self._setup_sybils(count=3)

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

    def _setup_sybils(self, count):
        """Generate keys and register multiple fake identities"""
        logger.info(f"Creating {count} Sybil identities...")
        for i in range(count):
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            sybil_id = f"{self.client_id}_sybil_{i+1}"

            self.sybils.append({
                'client_id': sybil_id,
                'private_key': priv,
                'public_key': pub
            })
            self._register_identity(sybil_id, pub)

    def _register_identity(self, cid, pub_key):
        """Helper to register any identity (main or sybil)"""
        try:
            pem = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            payload = {
                'client_id': cid,
                'num_samples': len(self.training_data[0]),
                'public_key': pem,
                'token': self.registration_token
            }

            response = requests.post(f'{self.server_url}/init_client', json=payload)
            if response.status_code == 200:
                data = response.json()
                logger.info(f"✅ Registered {cid}")
                if 'server_public_key' in data and not self.server_public_key:
                    self.server_public_key = serialization.load_pem_public_key(data['server_public_key'].encode())
            else:
                logger.error(f"Failed to register {cid}: {response.text}")
        except Exception as e:
            logger.error(f"Registration error: {e}")
            if cid == self.client_id: sys.exit(1)

    def fetch_model(self):
        try:
            response = requests.post(f'{self.server_url}/get_model', json={'client_id': self.client_id})
            data = response.json()

            if self.server_public_key and 'signature' in data:
                try:
                    payload_content = data['payload']
                    signature = base64.b64decode(data['signature'])
                    payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
                    self.server_public_key.verify(signature, payload_bytes)
                except Exception:
                    pass

            model_data = data['payload']
            weights = [np.array(w) for w in model_data['weights']]
            self.model.set_weights(weights)
            self.current_round = model_data['round']
            return True
        except Exception:
            return False

    def train_locally(self, epochs=2):
        X, y = self.training_data
        history = self.model.fit(X, y, epochs=epochs, batch_size=8, verbose=0)
        return float(history.history['loss'][-1]), float(history.history['accuracy'][-1])

    def _send_payload(self, client_id, private_key, weights, loss, accuracy, is_poisoned, attack_type):
        """Helper to sign and send a single payload"""
        payload_content = {
            'client_id': client_id,
            'weights': weights,
            'metrics': {
                'loss': loss, 'accuracy': accuracy,
                'timestamp': datetime.now().isoformat(),
                'attack_type': attack_type, 'is_poisoned': is_poisoned
            },
            'round': self.current_round
        }

        try:
            payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
            signature = private_key.sign(payload_bytes)
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            final_packet = {'payload': payload_content, 'signature': signature_b64}
            requests.post(f'{self.server_url}/submit_update', json=final_packet)
            logger.info(f"🚀 Sent update for {client_id}")
            return True
        except Exception as e:
            logger.error(f"Send failed for {client_id}: {e}")
            return False

    def submit_update(self, weights, loss, accuracy):
        # 1. Determine if attacking
        attacking = self.attack_mode != 'NONE' and self.current_round in self.attack_rounds

        # 2. Handle Sybil Attack (Special Case: Multiple Updates)
        if attacking and self.attack_mode == 'SYBIL_SIMULATION':
            logger.warning(f"EXECUTING SYBIL ATTACK with {len(self.sybils)} fake identities")

            # Create a "base" malicious update
            # Sybils send highly correlated updates
            base_weights = [np.array(w) for w in weights]

            # Generate updates for each sybil (Base + Tiny Noise to avoid exact dup detection)
            for i, sybil in enumerate(self.sybils):
                # Sybil Logic: Shift weights significantly (Attack) but keep them correlated
                # Here we just add noise to simulate distinct but conspiring clients
                sybil_weights = []
                for w in base_weights:
                    # 1.5x scaling to make it malicious + random jitter
                    # All sybils share the 1.5x trend (Correlation!)
                    jitter = np.random.normal(0, 0.01, w.shape)
                    poisoned_w = (w * 1.5) + jitter
                    sybil_weights.append(poisoned_w.tolist())

                self._send_payload(
                    sybil['client_id'],
                    sybil['private_key'],
                    sybil_weights,
                    loss, accuracy,
                    is_poisoned=True,
                    attack_type='SYBIL_SIMULATION'
                )
            return True

        # 3. Handle Other Attacks (Single Client)
        final_weights = weights
        is_poisoned = False
        attack_type = 'NONE'

        if attacking:
            is_poisoned = True
            attack_type = self.attack_mode
            if self.attack_mode == 'POISONING':
                final_weights = [(np.array(w) * 100.0).tolist() for w in weights]
            elif self.attack_mode == 'STEALTHY':
                # Constrain and scale
                final_weights = [(np.array(w) * 1.5).tolist() for w in weights]
            elif self.attack_mode == 'GRADIENT_INVERSION':
                final_weights = [(np.array(w) * 20.0).tolist() for w in weights]
        else:
            final_weights = [w.tolist() for w in weights]

        return self._send_payload(
            self.client_id, self.private_key, final_weights, loss, accuracy, is_poisoned, attack_type
        )

    def run_training_cycle(self):
        logger.info(f"Training Cycle (Round {self.current_round})")
        if not self.fetch_model(): return False
        loss, accuracy = self.train_locally(epochs=2)
        weights = self.model.get_weights()
        return self.submit_update(weights, loss, accuracy)

def main():
    client_id = os.getenv('CLIENT_ID', 'malicious_client')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'/data/{client_id}_data.json')
    attack_mode = os.getenv('ATTACK_MODE', 'NONE')

    logger.info(f"Starting MALICIOUS CLIENT: {client_id} (Mode: {attack_mode})")

    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            break
        except:
            time.sleep(2)

    client = MaliciousClient(client_id, server_url, data_file, attack_mode)

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
        except Exception:
            time.sleep(5)

if __name__ == '__main__':
    main()