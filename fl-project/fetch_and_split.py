import os
import json
import requests
import re
from collections import Counter

def fetch_and_split():
    # 1. Download dataset
    url = "https://raw.githubusercontent.com/sonu2759/Next-Word-Prediction-using-LSTM/master/sherlock-holm.es_stories_plain-text_advs.txt"
    print(f"Downloading dataset from {url}...")
    text = requests.get(url).text.lower()
    
    # 2. Basic Cleaning
    text = re.sub(r'[^\w\s]', '', text)  # Remove punctuation
    words = text.split()

    # 3. Create Vocabulary (Top 1000 words as per your client.py)
    vocab_size = 1000
    common_words = [word for word, count in Counter(words).most_common(vocab_size - 1)]
    word_to_id = {word: i + 1 for i, word in enumerate(common_words)}
    word_to_id["<UNK>"] = 0 # Out-of-vocabulary token

    # 4. Generate Trigrams (3 words input -> 1 word output)
    sequences = []
    for i in range(len(words) - 3):
        # Map words to IDs, use 0 if word not in top 1000
        seq = [word_to_id.get(w, 0) for w in words[i:i+4]]
        sequences.append(seq)

    # 5. Split for clients (e.g., first 5000 for client_1, next 5000 for malicious)
    os.makedirs('data', exist_ok=True)
    
    client_data = {
        "client_1": sequences[:5000],
        "malicious_client": sequences[5000:10000]
    }

    for client_id, data in client_data.items():
        with open(f"data/{client_id}_data.json", 'w') as f:
            json.dump(data, f)
        print(f"Saved {len(data)} sequences to data/{client_id}_data.json")

if __name__ == "__main__":
    fetch_and_split()