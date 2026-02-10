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
        
        # ADDED: Security - Registration token and cryptographic keys
        self.registration_token = os.getenv('REGISTRATION_TOKEN')
        self.server_public_key = None
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Create model structure (with random initial weights)
        self.model = self._create_model()
        
        # Load training data
        self.training_data = self._load_data(data_file)
        self.current_round = 0
        
        self.logger.info(f"Initialized client")
        
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
            # ADDED: Serialize public key to PEM format
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            response = requests.post(
                f'{self.server_url}/init_client',
                json={
                    'client_id': self.client_id,
                    'num_samples': len(self.training_data[0]),
                    'public_key': pem,  # ADDED
                    'token': self.registration_token  # ADDED
                }
            )
            
            data = response.json()
            
            # ADDED: Store server's public key for signature verification
            if 'server_public_key' in data:
                self.server_public_key = serialization.load_pem_public_key(
                    data['server_public_key'].encode()
                )
                self.logger.info("Server public key received and stored")
            
            # CRITICAL: Set initial weights from server
            if 'initial_weights' in data:
                weights = [np.array(w) for w in data['initial_weights']]
                self.model.set_weights(weights)
                self.current_round = data['round']
                self.logger.info(f"✓ Registered with server and received initial model (round {self.current_round})")
                self.logger.info(f"✓ Model synchronized with server's global model")
            else:
                self.logger.warning("⚠ No initial weights received from server!")
                self.logger.warning("⚠ Model may not be synchronized!")
                
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
            
            # ADDED: Verify server signature if available
            if self.server_public_key and 'signature' in data:
                try:
                    payload_content = data['payload']
                    signature = base64.b64decode(data['signature'])
                    payload_bytes = json.dumps(payload_content, sort_keys=True).encode()
                    self.server_public_key.verify(signature, payload_bytes)
                    self.logger.info("✓ Global model signature VALIDATED")
                    
                    weights = [np.array(w) for w in payload_content['weights']]
                    self.current_round = payload_content['round']
                except Exception as e:
                    self.logger.critical(f"🔴 SECURITY ALERT: Server signature INVALID! {e}")
                    return False
            else:
                # Backward compatibility: no signature
                weights = [np.array(w) for w in data['weights']]
                self.current_round = data['round']
            
            self.model.set_weights(weights)
            self.logger.info(f"✓ Fetched latest global model from server (round {self.current_round})")
            return True
        except Exception as e:
            self.logger.error(f"Failed to fetch model: {e}")
            return False
    
    def train_locally(self, epochs=2):
        self.logger.info(f"Starting local training ({epochs} epochs)")
        try:
            X, y = self.training_data
            
            self.logger.debug(f"Training data shape: X={X.shape}, y={y.shape}")
            
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
        except Exception as e:
            self.logger.error(f"Training failed with error: {e}")
            self.logger.exception(e)
            # Return dummy values so client doesn't crash
            return 999.9, 0.0
    
    def submit_update(self, loss, accuracy):
        try:
            weights = [w.tolist() for w in self.model.get_weights()]
            
            # MODIFIED: Create signed payload
            payload_content = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat()
                },
                'round': self.current_round  # ADDED
            }
            
            # ADDED: Sign the payload
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
                self.logger.info(f"✓ Update submitted successfully")
                return True
            else:
                self.logger.error(f"✗ Update rejected: {response.text}")
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
                data = response.json()
                status = data.get('status')
                
                # Only return True if server explicitly says to train
                if status == 'go_train':
                    # Update our round number to match server
                    if 'round' in data:
                        server_round = data['round']
                        if server_round != self.current_round:
                            self.logger.info(f"Server advanced to round {server_round} (was {self.current_round})")
                            self.current_round = server_round
                    return True
                elif status == 'already_served_this_round':
                    # Client already trained this round, wait for next
                    self.logger.debug("Already served for current round, waiting for next round...")
                    return False
                else:
                    self.logger.debug(f"Server status: {status}")
                    return False
            else:
                self.logger.warning(f"Unexpected status code from server: {response.status_code}")
            return False
        except requests.Timeout:
            self.logger.debug("Timeout waiting for signal")
            return False
        except Exception as e:
            self.logger.error(f"Error waiting for signal: {e}")
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
            logger.info("✓ Server is ready")
            break
        except:
            logger.info(f"Waiting for server ({attempt + 1}/10)")
            time.sleep(2)
    
    # Initialize client (this will sync with server's initial model)
    client = FLClient(client_id, server_url, data_file)
    
    # Main loop: wait for signal, train, repeat
    logger.info("Entering main loop - waiting for training signals")
    consecutive_waits = 0
    while True:
        try:
            # Wait for server to signal a training round
            logger.debug(f"Polling server for training signal (attempt {consecutive_waits + 1})...")
            if client.wait_for_server_signal(timeout=300):
                logger.info(f"🔔 Received training signal from server")
                consecutive_waits = 0  # Reset counter
                success = client.run_training_cycle()
                if success:
                    logger.info("✓ Training cycle completed successfully")
                else:
                    logger.warning("⚠️ Training cycle failed")
            else:
                consecutive_waits += 1
                if consecutive_waits % 12 == 0:  # Log every minute (12 * 5s)
                    logger.info(f"Still waiting for signal... ({consecutive_waits * 5}s elapsed)")
                logger.debug("No training signal received, waiting...")
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Client shutting down")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            logger.exception(e)  # Print full stack trace
            time.sleep(5)

if __name__ == '__main__':
    main()