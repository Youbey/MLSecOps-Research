#!/usr/bin/env python3
"""
Enhanced FL Model Training Script with Dataset Support

Supports:
  - Hugging Face Datasets (WikiText, AG News, etc.)
  - CSV files
  - Plain text files
  - LEAF Federated Datasets

Usage:
  # WikiText (recommended)
  python train_model_enhanced.py --dataset wikitext --samples 5000
  
  # Custom CSV
  python train_model_enhanced.py --dataset custom --dataset-file data.csv --text-column text
  
  # Custom text file
  python train_model_enhanced.py --dataset custom --dataset-file input.txt
  
  # LEAF federated
  python train_model_enhanced.py --dataset leaf --leaf-dataset shakespeare
"""

import os
import json
import numpy as np
import tensorflow as tf
import argparse
import logging
from datetime import datetime
from typing import List, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("MODEL-TRAINER")

# ============================================================================
# DATASET LOADERS
# ============================================================================

class DatasetLoader:
    """Load datasets from various sources"""
    
    @staticmethod
    def load_huggingface(dataset_name: str, config: str, num_samples: int) -> Optional[List[str]]:
        """Load dataset from Hugging Face Hub"""
        logger.info(f"Loading {dataset_name} ({config}) from Hugging Face...")
        
        try:
            from datasets import load_dataset
        except ImportError:
            logger.error("Install datasets: pip install datasets huggingface-hub")
            return None
        
        try:
            # Map config names to correct names
            config_map = {
                'wikitext-2': 'wikitext-2-v1',
                'wikitext-2-raw': 'wikitext-2-raw-v1',
                'wikitext-103': 'wikitext-103-v1',
                'wikitext-103-raw': 'wikitext-103-raw-v1',
            }
            
            # Use mapped config if available
            actual_config = config_map.get(config, config)
            logger.info(f"Using config: {actual_config}")
            
            dataset = load_dataset(dataset_name, actual_config)
            texts = []
            
            # Get from train split
            split = dataset['train'] if 'train' in dataset else dataset[list(dataset.keys())[0]]
            
            for i, sample in enumerate(split):
                if i >= num_samples:
                    break
                
                # Extract text field
                if isinstance(sample, dict):
                    # Try common text field names
                    for key in ['text', 'content', 'document', 'sentence']:
                        if key in sample:
                            text = sample[key]
                            break
                    else:
                        text = str(list(sample.values())[0])
                else:
                    text = str(sample)
                
                if text and len(text.strip()) > 0:
                    texts.append(text)
            
            logger.info(f"Loaded {len(texts)} samples from {dataset_name}")
            return texts if texts else None
        
        except Exception as e:
            logger.error(f"Failed to load from Hugging Face: {e}")
            return None
    
    @staticmethod
    def load_csv(filepath: str, text_column: str = 'text', num_samples: int = None) -> Optional[List[str]]:
        """Load text from CSV file"""
        logger.info(f"Loading from CSV: {filepath}")
        
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return None
        
        try:
            import pandas as pd
        except ImportError:
            logger.error("Install pandas: pip install pandas")
            return None
        
        try:
            df = pd.read_csv(filepath)
            
            if text_column not in df.columns:
                logger.error(f"Column '{text_column}' not found. Available: {list(df.columns)}")
                return None
            
            texts = df[text_column].astype(str).tolist()
            texts = [t.strip() for t in texts if len(t.strip()) > 0]
            
            if num_samples:
                texts = texts[:num_samples]
            
            logger.info(f"Loaded {len(texts)} samples from {filepath}")
            return texts if texts else None
        
        except Exception as e:
            logger.error(f"Failed to load CSV: {e}")
            return None
    
    @staticmethod
    def load_text_file(filepath: str, num_samples: int = None) -> Optional[List[str]]:
        """Load text from plain text file"""
        logger.info(f"Loading from text file: {filepath}")
        
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            
            # Split into paragraphs or lines
            chunks = [c.strip() for c in text.split('\n\n') if c.strip()]
            
            if not chunks:
                chunks = [c.strip() for c in text.split('\n') if c.strip()]
            
            if num_samples:
                chunks = chunks[:num_samples]
            
            logger.info(f"Loaded {len(chunks)} samples from {filepath}")
            return chunks if chunks else None
        
        except Exception as e:
            logger.error(f"Failed to load text file: {e}")
            return None
    
    @staticmethod
    def load_leaf(leaf_dataset: str, num_samples: int = None) -> Optional[List[str]]:
        """Load from LEAF federated dataset"""
        logger.info(f"Loading LEAF {leaf_dataset} dataset...")
        
        leaf_path = f'./leaf/data/{leaf_dataset}'
        
        if not os.path.exists(leaf_path):
            logger.error(f"LEAF dataset not found at {leaf_path}")
            logger.info("Download with: git clone https://github.com/TalwalkarLab/leaf.git")
            return None
        
        try:
            all_data = []
            
            # Get all client files
            for filename in os.listdir(f'{leaf_path}/data/train'):
                if filename.endswith('_X.json'):
                    try:
                        with open(f'{leaf_path}/data/train/{filename}') as f:
                            client_data = json.load(f)
                        
                        if isinstance(client_data, list):
                            all_data.extend(client_data)
                        else:
                            all_data.append(str(client_data))
                    
                    except Exception as e:
                        logger.warning(f"Failed to load {filename}: {e}")
            
            # Clean data
            all_data = [str(d).strip() for d in all_data if d]
            
            if num_samples:
                all_data = all_data[:num_samples]
            
            logger.info(f"Loaded {len(all_data)} samples from LEAF {leaf_dataset}")
            return all_data if all_data else None
        
        except Exception as e:
            logger.error(f"Failed to load LEAF: {e}")
            return None

# ============================================================================
# DATA PROCESSING
# ============================================================================

class DataProcessor:
    """Process raw text into training sequences"""
    
    @staticmethod
    def texts_to_sequences(texts: List[str], vocab_size: int = 10000, 
                          sequence_length: int = 3) -> Tuple[np.ndarray, np.ndarray]:
        """Convert texts to n-gram sequences for language modeling"""
        
        logger.info(f"Processing {len(texts)} texts into sequences...")
        
        try:
            from tensorflow.keras.preprocessing.text import Tokenizer
        except ImportError:
            logger.error("TensorFlow not installed")
            return None, None
        
        # Filter empty texts
        texts = [t for t in texts if t and len(t.strip()) > 0]
        
        if not texts:
            logger.error("No valid texts to process")
            return None, None
        
        # Tokenize
        logger.info(f"Tokenizing {len(texts)} texts (vocab_size={vocab_size})...")
        tokenizer = Tokenizer(num_words=vocab_size, oov_token='<unk>')
        tokenizer.fit_on_texts(texts)
        sequences = tokenizer.texts_to_sequences(texts)
        
        # Create n-grams
        logger.info(f"Creating {sequence_length}-grams...")
        X, y = [], []
        
        for seq in sequences:
            if len(seq) > sequence_length:
                for i in range(len(seq) - sequence_length):
                    X.append(seq[i:i+sequence_length])
                    y.append(seq[i+sequence_length])
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"Created {len(X)} training sequences")
        
        if len(X) == 0:
            logger.error("No sequences created! Data might be too short.")
            return None, None
        
        return X, y

# ============================================================================
# MODEL TRAINER
# ============================================================================

class ModelTrainer:
    """Train and save the global FL model"""
    
    def __init__(self, output_path: str = './global_model.h5', 
                 weights_path: str = './global_model_weights.json'):
        self.output_path = output_path
        self.weights_path = weights_path
        self.model = None
        logger.info(f"Trainer initialized - output: {output_path}")
    
    def create_model(self) -> tf.keras.Model:
        """Create LSTM language model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(10000, 100, input_length=3),
            tf.keras.layers.LSTM(150),
            tf.keras.layers.Dense(10000, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        model.build(input_shape=(None, 3))
        logger.info("Model created: Embedding(10000,100) → LSTM(150) → Dense(10000)")
        return model
    
    def train(self, X: np.ndarray, y: np.ndarray, epochs: int = 5, 
              batch_size: int = 32, validation_split: float = 0.2):
        """Train model on data"""
        self.model = self.create_model()
        
        logger.info(f"Training on {len(X)} samples for {epochs} epochs (batch_size={batch_size})")
        
        history = self.model.fit(
            X, y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=1
        )
        
        final_loss = float(history.history['loss'][-1])
        final_acc = float(history.history['accuracy'][-1])
        final_val_loss = float(history.history['val_loss'][-1])
        final_val_acc = float(history.history['val_accuracy'][-1])
        
        logger.info(f"Training complete!")
        logger.info(f"  Training loss: {final_loss:.4f}, accuracy: {final_acc:.4f}")
        logger.info(f"  Validation loss: {final_val_loss:.4f}, accuracy: {final_val_acc:.4f}")
        
        return history
    
    def save_model_h5(self) -> bool:
        """Save model to HDF5 format"""
        if self.model is None:
            logger.error("No model to save. Train first!")
            return False
        
        try:
            self.model.save(self.output_path, save_format='h5')
            size_mb = os.path.getsize(self.output_path) / 1024 / 1024
            logger.info(f"Model saved to {self.output_path} ({size_mb:.2f} MB)")
            return True
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def save_weights_json(self) -> bool:
        """Save weights to JSON format"""
        if self.model is None:
            logger.error("No model to save. Train first!")
            return False
        
        try:
            weights = [w.tolist() for w in self.model.get_weights()]
            data = {
                'timestamp': datetime.now().isoformat(),
                'model_type': 'LSTM Language Model',
                'architecture': {
                    'vocab_size': 10000,
                    'embedding_dim': 100,
                    'lstm_units': 150,
                    'output_vocab_size': 10000
                },
                'weights': weights
            }
            with open(self.weights_path, 'w') as f:
                json.dump(data, f)
            
            size_mb = os.path.getsize(self.weights_path) / 1024 / 1024
            logger.info(f"Weights saved to {self.weights_path} ({size_mb:.2f} MB)")
            return True
        except Exception as e:
            logger.error(f"Failed to save weights: {e}")
            return False
    
    def get_model_summary(self):
        """Print model summary"""
        if self.model is None:
            logger.error("No model. Train first!")
            return
        
        logger.info("=" * 70)
        logger.info("MODEL SUMMARY")
        logger.info("=" * 70)
        self.model.summary()
        logger.info("=" * 70)

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Train FL global model with various datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # WikiText (recommended for quick start)
  python train_model_enhanced.py --dataset wikitext --samples 5000 --epochs 10
  
  # Custom CSV
  python train_model_enhanced.py --dataset custom --dataset-file data.csv --text-column text
  
  # Custom text file
  python train_model_enhanced.py --dataset custom --dataset-file input.txt
  
  # LEAF Shakespeare
  python train_model_enhanced.py --dataset leaf --leaf-dataset shakespeare --samples 5000
  
  # Just show model
  python train_model_enhanced.py --summary
        """)
    
    # Dataset selection
    parser.add_argument('--dataset', 
                       choices=['wikitext', 'ag_news', 'custom', 'leaf'],
                       default='wikitext',
                       help='Dataset source (default: wikitext)')
    
    # HuggingFace options
    parser.add_argument('--config', default='wikitext-2',
                       help='Dataset config for HuggingFace (default: wikitext-2)')
    
    # Custom dataset options
    parser.add_argument('--dataset-file', 
                       help='Path to custom dataset file (CSV or TXT)')
    parser.add_argument('--text-column', default='text',
                       help='Column name for text in CSV file (default: text)')
    
    # LEAF options
    parser.add_argument('--leaf-dataset', default='shakespeare',
                       help='LEAF dataset name (default: shakespeare)')
    
    # Training options
    parser.add_argument('--epochs', type=int, default=5,
                       help='Training epochs (default: 5)')
    parser.add_argument('--batch-size', type=int, default=32,
                       help='Batch size (default: 32)')
    parser.add_argument('--samples', type=int, default=5000,
                       help='Number of samples to use (default: 5000)')
    
    # Output options
    parser.add_argument('--output', default='./global_model.h5',
                       help='Output model file (default: ./global_model.h5)')
    parser.add_argument('--output-json', default='./global_model_weights.json',
                       help='Output weights JSON file (default: ./global_model_weights.json)')
    parser.add_argument('--format', choices=['h5', 'json', 'both'], default='both',
                       help='Save format (default: both)')
    
    # Other options
    parser.add_argument('--summary', action='store_true',
                       help='Print model summary and exit')
    
    args = parser.parse_args()
    
    # Create trainer
    trainer = ModelTrainer(args.output, args.output_json)
    
    # Show summary only
    if args.summary:
        logger.info("Creating and displaying model summary...")
        trainer.model = trainer.create_model()
        trainer.get_model_summary()
        return
    
    # Load dataset
    logger.info(f"Dataset: {args.dataset}")
    
    if args.dataset == 'wikitext':
        texts = DatasetLoader.load_huggingface('wikitext', args.config, args.samples)
    
    elif args.dataset == 'ag_news':
        texts = DatasetLoader.load_huggingface('ag_news', 'default', args.samples)
    
    elif args.dataset == 'custom':
        if not args.dataset_file:
            logger.error("--dataset-file required for custom dataset")
            return
        
        if args.dataset_file.endswith('.csv'):
            texts = DatasetLoader.load_csv(args.dataset_file, args.text_column, args.samples)
        else:
            texts = DatasetLoader.load_text_file(args.dataset_file, args.samples)
    
    elif args.dataset == 'leaf':
        texts = DatasetLoader.load_leaf(args.leaf_dataset, args.samples)
    
    else:
        logger.error(f"Unknown dataset: {args.dataset}")
        return
    
    if texts is None or len(texts) == 0:
        logger.error("Failed to load dataset or dataset is empty")
        return
    
    logger.info(f"Loaded {len(texts)} texts")
    
    # Process data
    X, y = DataProcessor.texts_to_sequences(texts, vocab_size=10000, sequence_length=3)
    
    if X is None or len(X) == 0:
        logger.error("Failed to process data")
        return
    
    # Train
    trainer.train(X, y, epochs=args.epochs, batch_size=args.batch_size)
    
    # Save
    logger.info(f"Saving model in {args.format} format...")
    
    if args.format in ['h5', 'both']:
        trainer.save_model_h5()
    
    if args.format in ['json', 'both']:
        trainer.save_weights_json()
    
    logger.info("=" * 70)
    logger.info("TRAINING COMPLETE!")
    logger.info("=" * 70)
    logger.info(f"Model ready to use with server:")
    logger.info(f"  SERVER_MODEL_PATH={args.output} python server.py")

if __name__ == '__main__':
    main()