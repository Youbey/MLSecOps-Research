"""
Generate synthetic word prediction data for FL clients.
Creates word sequences for autocomplete training.
"""

import json
import numpy as np
import os

def generate_client_data(client_id, num_samples=200):
    """
    Generate word prediction training data.
    Input: sequence of 3 word indices
    Output: next word index (1000 possible words)
    """
    np.random.seed(client_id)  # Different data per client
    
    X = np.random.randint(0, 1000, size=(num_samples, 3))
    y = np.random.randint(0, 1000, size=(num_samples, 1))
    
    # Add some patterns per client for diversity
    if client_id == 1:
        # Client 1: higher probability of words in range 0-300
        y = np.random.randint(0, 300, size=(num_samples, 1))
    elif client_id == 2:
        # Client 2: higher probability of words in range 300-600
        y = np.random.randint(300, 600, size=(num_samples, 1))
    
    data = {
        'X': X.tolist(),
        'y': y.tolist(),
        'num_samples': num_samples,
        'vocab_size': 1000,
        'client_id': f'client_{client_id}'
    }
    
    return data

def main():
    os.makedirs('data', exist_ok=True)
    
    for client_id in [1, 2]:
        data = generate_client_data(client_id, num_samples=200)
        filename = f'data/client_{client_id}_data.json'
        
        with open(filename, 'w') as f:
            json.dump(data, f)
        
        print(f"Generated {filename}: {data['num_samples']} samples")

if __name__ == '__main__':
    main()
