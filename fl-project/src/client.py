import os
import sys
import json
import numpy as np
import tensorflow as tf
import requests
import time
import logging
from datetime import datetime

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
        self.model = self._create_model()
        self.training_data = self._load_data(data_file)
        self.current_round = 0
        
        self.logger.info(f"Initialized client")
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
            self.logger.info(f"Registered with server")
        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
    
    def fetch_model(self):
        try:
            response = requests.post(
                f'{self.server_url}/get_model',
                json={'client_id': self.client_id}
            )
            data = response.json()
            weights = [np.array(w) for w in data['weights']]
            self.model.set_weights(weights)
            self.current_round = data['round']
            self.logger.info(f"Fetched model from round {self.current_round}")
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
            
            payload = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            response = requests.post(
                f'{self.server_url}/submit_update',
                json=payload
            )

            if response.status_code == 200:
                self.logger.info(f"Update submitted successfully")
                return True
            else:
                self.logger.error(f"Update rejected: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to submit update: {e}")
            return False
    
    def run_training_cycle(self):
        self.logger.info(f"Starting training cycle")
        
        if not self.fetch_model():
            return False
        
        loss, accuracy = self.train_locally(epochs=2)
        
        if not self.submit_update(loss, accuracy):
            return False
        
        self.logger.info(f"Training cycle completed")
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
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            logger.info("Server is ready")
            break
        except:
            logger.info(f"Waiting for server ({attempt + 1}/10)")
            time.sleep(2)
    
    client = FLClient(client_id, server_url, data_file)
    
    # Main loop: wait for signal, train, repeat
    logger.info("Entering main loop - waiting for training signals")
    while True:
        try:
            # Wait for server to signal a training round
            if client.wait_for_server_signal(timeout=300):
                logger.info(f"Received training signal from server")
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