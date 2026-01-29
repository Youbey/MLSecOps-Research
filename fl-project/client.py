import os
import sys
import json
import numpy as np
import tensorflow as tf
import requests
import time
import logging
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"FL-Client")

class FLClient:
    def __init__(self, client_id, server_url, data_file):
        self.client_id = client_id
        self.server_url = server_url
        self.model = self._create_model()
        self.training_data = self._load_data(data_file)
        self.round = 0
        self.update_history = []
        
        logger.info(f"Client {client_id} initialized")
        self._register_with_server()
      
    def _create_model(self):
        # Match server's vocab size of 10000
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(1000, 64, input_length=3),
            tf.keras.layers.LSTM(64),
            tf.keras.layers.Dense(1000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        
        # Build the model to initialize weights without dummy data
        model.build(input_shape=(None, 3))
        
        return model
    
    def _load_data(self, data_file):
        """Load training data from file (Compatible with Medium Article N-Grams)"""
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        # The data is now a list of sequences [word1, word2, word3, target]
        data_array = np.array(data)
        
        # Split into X (first 3 words) and y (last word)
        X = data_array[:, :-1]
        y = data_array[:, -1]
        
        logger.info(f"Loaded {len(X)} samples for client {self.client_id}")
        return X, y
    
    def _register_with_server(self):
        """Register client with server"""
        try:
            response = requests.post(
                f'{self.server_url}/init_client',
                json={
                    'client_id': self.client_id,
                    'num_samples': len(self.training_data[0])
                }
            )
            logger.info(f"Registered: {response.json()}")
        except Exception as e:
            logger.error(f"Registration failed: {e}")
    
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
            self.round = data['round']
            model_hash = data.get('model_hash', 'unknown')
            logger.info(f"Fetched model from round {self.round} (hash: {model_hash})")
            return True
        except Exception as e:
            logger.error(f"Failed to fetch model: {e}")
            return False
    
    def train_locally(self, epochs=1):
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
            
            payload = {
                'client_id': self.client_id,
                'weights': weights,
                'metrics': {
                    'loss': loss,
                    'accuracy': accuracy,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            size_bytes = len(json.dumps(payload))
            response = requests.post(
                f'{self.server_url}/submit_update',
                json=payload
            )
            
            logger.info(f"Update submitted: {size_bytes} bytes, "
                       f"status={response.json().get('status')}")
            return True
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
    for attempt in range(10):
        try:
            requests.get(f'{server_url}/health', timeout=2)
            break
        except:
            logger.info(f"Waiting for server... ({attempt + 1}/10)")
            time.sleep(2)
    
    client = FLClient(client_id, server_url, data_file)
    
    # Run single training cycle (not continuous)
    cycle = 1
    logger.info(f"\n>>> Cycle {cycle}")
    client.run_training_cycle()
    logger.info(f" Training complete. Client exiting.")

if __name__ == '__main__':
    main()