import os
import json
import requests
import re
import numpy as np
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

def prepare_federated_data():
    # URL for Sherlock Holmes from Project Gutenberg
    url = "https://www.gutenberg.org/cache/epub/1661/pg1661.txt"
    print("Downloading dataset from Project Gutenberg...")
    
    response = requests.get(url)
    text = response.text.lower()

    # Article cleaning: Remove non-alphabetic characters but keep spaces
    text = re.sub(r'[^a-z\s]', '', text)
    
    # Article step: Tokenizer process
    tokenizer = Tokenizer()
    tokenizer.fit_on_texts([text])
    total_words = len(tokenizer.word_index) + 1
    print(f"Total vocabulary size: {total_words}")

    # Article step: N-gram generation
    # This splits text by line and creates sliding windows (e.g., "the", "the adventures", "the adventures of")
    input_sequences = []
    for line in text.split('\n'):
        token_list = tokenizer.texts_to_sequences([line])[0]
        for i in range(1, len(token_list)):
            n_gram_sequence = token_list[:i+1]
            input_sequences.append(n_gram_sequence)

    # Article step: Pre-Padding
    # We use a max_sequence_len of 4 (3 words context + 1 target) to match your current model
    max_sequence_len = 4 
    input_sequences = np.array(pad_sequences(input_sequences, maxlen=max_sequence_len, padding='pre'))
    
    print(f"Total sequences generated: {len(input_sequences)}")
    os.makedirs('data', exist_ok=True)

    # Split sequences for the clients (5,000 samples each)
    client_data = {
        "client_1": input_sequences[:200].tolist(),
        "malicious_client": input_sequences[200:400].tolist()
    }

    for client_id, data in client_data.items():
        file_path = f"data/{client_id}_data.json"
        with open(file_path, 'w') as f:
            json.dump(data, f)
        print(f"Saved {len(data)} sequences to {file_path}")

if __name__ == "__main__":
    prepare_federated_data()