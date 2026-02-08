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
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class FLClient:
    def __init__(self, client_id, server_url, data_file):
        self.client_id = client_id
        self.server_url = server_url
        self.logger = logging.getLogger(f"CLIENT-{client_id}")
        
        # Security: Registration token and cryptographic keys
        self.registration_token = os.getenv('REGISTRATION_TOKEN')
        self.server_public_key = None
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Create model structure (with random initial weights)
        self.model = self._create_model()
        
        # Load training data
        self.training_data = self._load_data(data_file)
        self.current_round = 0
        
        self.logger.info(f"Initialized client with secure cryptographic keys")
        
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
        try:
            with open(data_file, 'r') as f:
                data = json.load(f)
            data_array = np.array(data)
            X = data_array[:, :-1]
            y = data_array[:, -1]
            self.logger.info(f"Loaded {len(X)} training samples")
            return X, y
        except Exception as e:
            self.logger.error(f"Failed to load data: {e}")
            sys.exit(1)
    
    def _register_with_server(self):
        try:
            # Serialize public key to PEM format
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
            
            response = requests.post(
                f'{self.server_url}/init_client',
                json=payload
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Store server's public key for signature verification
                if 'server_public_key' in data:
                    self.server_public_key = serialization.load_pem_public_key(
                        data['server_public_key'].encode()
                    )
                    self.logger.info(" Server public key received and stored")
                
                # CRITICAL: Set initial weights from server
                if 'initial_weights' in data:
                    weights = [np.array(w) for w in data['initial_weights']]
                    self.model.set_weights(weights)
                    self.current_round = data['round']
                    self.logger.info(f" Registered with server and received initial model (round {self.current_round})")
                    self.logger.info(f" Model synchronized with server's global model")
                else:
                    self.current_round = data.get('round', 0)
                    self.logger.warning(" No initial weights received from server!")
                    self.logger.warning(" Model may not be synchronized!")
            else:
                self.logger.error(f"Registration failed: {response.text}")
                sys.exit(1)
                
        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
            sys.exit(1)
    
    def fetch_model(self):
        """Fetch the latest global model from server before training"""
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            
            if response.status_code != 200:
                self.logger.error(f"Failed to fetch model: {response.status_code}")
                return False
            
            data = response.json()
            
            # Verify server signature if available
            if self.server_public_key and 'signature' in data:
                try:
                    payload_content = data['payload']
                    signature = base64.b64decode(data['signature'])
                    payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
                    self.server_public_key.verify(signature, payload_bytes)
                    self.logger.info(" Global model signature VALIDATED")
                    
                    # Extract model data from signed payload
                    model_data = payload_content
                except Exception as e:
                    self.logger.critical(f" SECURITY ALERT: Server signature INVALID! {e}")
                    return False
            else:
                # No signature, use data directly (backward compatibility)
                model_data = data
            
            weights = [np.array(w) for w in model_data.get('weights', data.get('weights', []))]
            self.model.set_weights(weights)
            self.current_round = model_data.get('round', data.get('round', 0))
            self.logger.info(f" Fetched latest global model from server (round {self.current_round})")
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
    
    def submit_update(self, loss, accuracy):
        try:
            weights = [w.tolist() for w in self.model.get_weights()]
            
            # Create payload
            payload_content = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat()
                },
                'round': self.current_round
            }
            
            # Sign the payload
            payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
            signature = self.private_key.sign(payload_bytes)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Send signed payload
            final_packet = {
                'payload': payload_content,
                'signature': signature_b64
            }
            
            response = requests.post(
                f'{self.server_url}/submit_update',
                json=final_packet
            )

            if response.status_code == 200:
                self.logger.info(f" Update submitted successfully (signed)")
                return True
            else:
                self.logger.error(f" Update rejected: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to submit update: {e}")
            return False
    
    def run_training_cycle(self):
        """
        Complete training cycle:
        1. Fetch latest global model from server
        2. Train locally
        3. Submit weight updates
        """
        self.logger.info(f"╔══ Starting training cycle ══╗")
        
        # STEP 1: Fetch latest global model
        self.logger.info(f"[1/3] Fetching latest global model...")
        if not self.fetch_model():
            self.logger.error(f"Failed to fetch model, aborting cycle")
            return False
        
        # STEP 2: Train locally
        self.logger.info(f"[2/3] Training locally...")
        loss, accuracy = self.train_locally(epochs=2)
        
        # STEP 3: Submit update
        self.logger.info(f"[3/3] Submitting update to server...")
        if not self.submit_update(loss, accuracy):
            self.logger.error(f"Failed to submit update")
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
            self.logger.error(f"Error waiting for signal: {e}")
            return False
        return False

def main():
    client_id = os.getenv('CLIENT_ID', 'client_1')
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    data_file = os.getenv('DATA_FILE', f'data/{client_id}_data.json')
    
    # Wait for server to start
    logger = logging.getLogger(f"CLIENT-{client_id}")
    logger.info("Waiting for server to be ready...")
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            logger.info(" Server is ready")
            break
        except:
            logger.info(f"Waiting for server ({attempt + 1}/10)")
            time.sleep(2)
    
    # Initialize client (this will sync with server's initial model)
    client = FLClient(client_id, server_url, data_file)
    
    # Main loop: wait for signal, train, repeat
    logger.info("Entering main loop - waiting for training signals")
    
    # Alternative: Poll server health for new rounds
    last_processed_round = -1
    while True:
        try:
            # Check server for new rounds
            response = requests.get(f'{server_url}/health', timeout=5)
            if response.status_code == 200:
                server_round = response.json().get('round', 0)
                
                if server_round > last_processed_round:
                    logger.info(f" New Round Detected: {server_round}")
                    client.current_round = server_round
                    if client.run_training_cycle():
                        last_processed_round = server_round
                    else:
                        time.sleep(5)
                else:
                    time.sleep(2)
            else:
                # Fallback to wait_for_round endpoint
                if client.wait_for_server_signal(timeout=300):
                    logger.info(f" Received training signal from server")
                    client.run_training_cycle()
                else:
                    time.sleep(5)
                    
        except KeyboardInterrupt:
            logger.info("Client shutting down")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()