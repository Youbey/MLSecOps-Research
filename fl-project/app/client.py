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
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"FL-Client")

class FLClient:
    def __init__(self, client_id, server_url, data_file):
        self.client_id = client_id
        self.server_url = server_url
        self.update_history = []
        self.registration_token = os.getenv('REGISTRATION_TOKEN')

        # 1. Génération des clés Ed25519 (Rapide & Sécurisé)
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.model = self._create_model()
        self.training_data = self._load_data(data_file)
        self.round = 0

        logger.info(f"Client {client_id} initialized with Secure Keys")
        self._register_with_server()

    def _create_model(self):
        # Match server's vocab size of 10000
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(10000, 100, input_length=3),
            tf.keras.layers.LSTM(150),
            tf.keras.layers.Dense(10000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

        # Build the model to initialize weights without dummy data
        model.build(input_shape=(None, 3))

        return model

    def _load_data(self, data_file):
        """Load training data from file (Compatible with Medium Article N-Grams)"""
        try:
            with open(data_file, 'r') as f:
                data = json.load(f)

            # The data is now a list of sequences [word1, word2, word3, target]
            data_array = np.array(data)

            # Split into X (first 3 words) and y (last word)
            X = data_array[:, :-1]
            y = data_array[:, -1]

            logger.info(f"Loaded {len(X)} samples for client {self.client_id}")
            return X, y
        except Exception as e:
            logger.error(f"Failed to load data from {data_file}: {e}")
            sys.exit(1)

    def _register_with_server(self):
        """Register sending Public Key + Token"""
        try:
            # Sérialisation de la clé publique en PEM pour l'envoi
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            payload = {
                'client_id': self.client_id,
                'num_samples': len(self.training_data[0]), # Correction index
                'public_key': pem,
                'token': self.registration_token  # Pre-shared secret
            }

            response = requests.post(f'{self.server_url}/init_client', json=payload)
            if response.status_code == 200:
                logger.info(f"Successfully Registered: {response.json()}")
            else:
                logger.error(f"Registration Failed: {response.text}")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Connection error: {e}")
            sys.exit(1)

    def fetch_model(self):
        """Download global model from server"""
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            if response.status_code != 200:
                logger.error(f"Failed to fetch model: {response.text}")
                return False

            data = response.json()
            weights = [np.array(w) for w in data['weights']]
            self.model.set_weights(weights)
            self.round = data['round']
            logger.info(f"Fetched model from round {self.round}")
            return True
        except Exception as e:
            logger.error(f"Failed to fetch model: {e}")
            return False

    def train_locally(self, epochs=2):
        """Train model locally"""
        logger.info(f"Starting local training for {epochs} epochs")
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

        logger.info(f"Local training completed: loss={loss:.4f}, accuracy={accuracy:.4f}")
        return loss, accuracy

    def submit_update(self, loss, accuracy):
        """Send local model update to server"""
        try:
            weights = [w.tolist() for w in self.model.get_weights()]

            # Payload doit contenir exactement la structure attendue par le serveur pour la signature
            payload_content = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat()
                },
                'round': self.round
            }

            # 2. Signature du contenu
            # On doit signer exactement les mêmes bytes que le serveur vérifiera
            payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
            signature = self.private_key.sign(payload_bytes)
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # Envoi de l'enveloppe signée
            final_packet = {
                'payload': payload_content,
                'signature': signature_b64
            }

            response = requests.post(f'{self.server_url}/submit_update', json=final_packet)

            if response.status_code == 200:
                logger.info(f"Secure Update accepted by server")
                return True
            else:
                logger.error(f"Update rejected: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Failed to submit update: {e}")
            return False

    def run_training_cycle(self):
        """Run one complete FL cycle: fetch -> train -> submit"""
        logger.info(f"=== Starting FL cycle ===")

        if not self.fetch_model():
            return False

        loss, accuracy = self.train_locally(epochs=2)

        if not self.submit_update(loss, accuracy):
            return False

        logger.info(f"=== FL cycle completed ===")
        return True

def main():
    client_id = os.getenv('CLIENT_ID', 'client_1')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'/data/{client_id}_data.json')

    logger.name = f"FL-Client-{client_id}"

    # Wait for server to start
    logger.info("Waiting for server to be ready...")
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            logger.info("Server is up!")
            break
        except:
            logger.info(f"Waiting for server... ({attempt + 1}/10)")
            time.sleep(2)

    client = FLClient(client_id, server_url, data_file)

    # Mode boucle pour attendre les rounds du serveur
    last_processed_round = -1

    # Pour le test Jenkins, on peut faire une boucle simple
    # ou une seule exécution si c'est ce que contrôle control.py
    # Ici, je mets la logique de boucle "smart" qui attend les rounds
    while True:
        try:
            response = requests.get(f'{server_url}/health', timeout=5)
            server_data = response.json()
            server_round = server_data.get('round', 0)

            if server_round > last_processed_round:
                logger.info(f">>> New Round Detected: {server_round}")
                client.round = server_round # Sync round explicitly
                if client.run_training_cycle():
                    last_processed_round = server_round
                else:
                    time.sleep(5) # Retry soon if failed
            else:
                time.sleep(2)

        except Exception as e:
            logger.error(f"Loop error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()