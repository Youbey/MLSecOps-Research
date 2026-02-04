"""
Detect Model Poisoning Attacks in FL

Attack Types:
1. Model Replacement (scaled attack) - Large updates that dominate aggregation
2. Constrain-and-Scale (stealthy) - Attacks that evade norm-based detection
3. Distributed Backdoor (DBA) - Multiple clients with sub-triggers

Defense: Anomaly detection on update characteristics
"""

import json
import numpy as np
from typing import Dict, List, Tuple
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PoisoningDetector")

# Import structured logger
try:
    from utils.structured_logger import logger as structured_logger
except ImportError:
    structured_logger = None

class PoisoningDetector:
    def __init__(self, threshold_std=2.5, history_window=10):
        """
        Args:
            threshold_std: Number of standard deviations for anomaly detection
            history_window: Number of rounds to keep in history
        """
        self.threshold_std = threshold_std
        self.history_window = history_window
        self.update_history = {}  # client_id -> list of metrics
        self.suspicion_scores = {}  # client_id -> scores
        
    def analyze_update(self, client_id: str, weights: list, previous_weights: list = None) -> dict:
            """
            Analyze a single client update for poisoning characteristics.
            Compatible with multi-layer LSTM models.
            """
            # FIX: Flatten the list of inhomogeneous weight tensors into one flat array
            flat_weights = np.concatenate([np.array(w).flatten() for w in weights]).astype(np.float32)
            
            metrics = {
                'client_id': client_id,
                'timestamp': datetime.now().isoformat(),
                'l2_norm': float(np.linalg.norm(flat_weights)),
                'max_weight': float(np.max(np.abs(flat_weights))),
                'mean_abs_weight': float(np.mean(np.abs(flat_weights))),
                'std_weight': float(np.std(flat_weights)),
            }
            
            # Compare with previous update if available
            if previous_weights is not None:
                # FIX: Flatten previous weights as well
                flat_prev = np.concatenate([np.array(w).flatten() for w in previous_weights]).astype(np.float32)
                delta = flat_weights - flat_prev
                metrics['weight_delta_norm'] = float(np.linalg.norm(delta))
                metrics['delta_ratio'] = float(metrics['weight_delta_norm'] / (metrics['l2_norm'] + 1e-10))
            
            # Store in history
            if client_id not in self.update_history:
                self.update_history[client_id] = []
            
            self.update_history[client_id].append(metrics)
            
            # Keep only recent history
            if len(self.update_history[client_id]) > self.history_window:
                self.update_history[client_id].pop(0)
            
            return metrics
    def detect_anomalies(self, all_client_metrics: Dict[str, Dict]) -> Dict:
        """
        Detect anomalous clients using statistical methods
        
        Attacks detected:
        1. Model Replacement: Very large L2 norms (scaled attacks)
        2. Constrain-and-Scale: Normal magnitude but unusual direction
        3. Distributed Backdoor: Multiple clients with correlated patterns
        """
        
        if not all_client_metrics:
            return {'alerts': [], 'analysis': {}}
        
        alerts = []
        analysis = {}
        
        # Extract metrics
        l2_norms = [m['l2_norm'] for m in all_client_metrics.values()]
        max_weights = [m['max_weight'] for m in all_client_metrics.values()]
        
        if not l2_norms:
            return {'alerts': [], 'analysis': {}}
        
        # Statistical anomaly detection
        l2_mean = np.mean(l2_norms)
        l2_std = np.std(l2_norms)
        
        max_mean = np.mean(max_weights)
        max_std = np.std(max_weights)
        
        analysis['l2_norm_stats'] = {
            'mean': float(l2_mean),
            'std': float(l2_std),
            'threshold': float(l2_mean + self.threshold_std * l2_std)
        }
        
        # ==========================================
        # ATTACK 1: Model Replacement Detection
        # ==========================================
        # Characteristic: Very large L2 norm (scaled update)
        for client_id, metrics in all_client_metrics.items():
            l2_norm = metrics['l2_norm']
            max_weight = metrics['max_weight']
            
            # Flagged if > mean + 2.5*std (statistically anomalous)
            if l2_norm > l2_mean + self.threshold_std * l2_std:
                confidence = min(1.0, (l2_norm - l2_mean) / (self.threshold_std * l2_std + 1e-10))
                alert = {
                    'type': 'MODEL_REPLACEMENT',
                    'severity': 'HIGH',
                    'client_id': client_id,
                    'reason': f'Anomalously large L2 norm: {l2_norm:.2f} (threshold: {l2_mean + self.threshold_std * l2_std:.2f})',
                    'confidence': float(confidence),
                    'metrics': {
                        'l2_norm': float(l2_norm),
                        'expected_l2_norm': float(l2_mean)
                    }
                }
                alerts.append(alert)
                
                # Log via structured logger
                if structured_logger:
                    structured_logger.log_attack_detected(
                        attack_type='MODEL_REPLACEMENT',
                        client_id=client_id,
                        confidence=confidence,
                        evidence={'l2_norm': float(l2_norm)}
                    )
        
        # ==========================================
        # ATTACK 2: Constrain-and-Scale (Stealthy)
        # ==========================================
        # Characteristic: Normal magnitude but unusual direction compared to majority
        if len(all_client_metrics) > 2:
            # Calculate "benign direction" as mean of all updates
            benign_direction = np.mean([
                m['std_weight'] for m in all_client_metrics.values()
            ])
            
            for client_id, metrics in all_client_metrics.items():
                # Check if std is unusually low (tightly scaled weights = suspicious)
                std_weight = metrics['std_weight']
                
                if std_weight < benign_direction * 0.3:  # 30% below average
                    alert = {
                        'type': 'CONSTRAIN_AND_SCALE',
                        'severity': 'MEDIUM',
                        'client_id': client_id,
                        'reason': f'Update has unusually tight weight distribution (low variance)',
                        'confidence': 0.6,
                        'metrics': {
                            'std_weight': float(std_weight),
                            'expected_std': float(benign_direction)
                        }
                    }
                    alerts.append(alert)
                    
                    # Log via structured logger
                    if structured_logger:
                        structured_logger.log_attack_detected(
                            attack_type='CONSTRAIN_AND_SCALE',
                            client_id=client_id,
                            confidence=0.6,
                            evidence={'std_weight': float(std_weight)}
                        )
        
        # ==========================================
        # ATTACK 3: Distributed Backdoor (Multi-client)
        # ==========================================
        # Characteristic: Multiple clients with highly correlated updates
        if len(all_client_metrics) > 2:
            client_ids = list(all_client_metrics.keys())
            
            for i, client_a in enumerate(client_ids):
                for client_b in client_ids[i+1:]:
                    # Calculate "update similarity" via weight statistics
                    mean_a = all_client_metrics[client_a]['mean_abs_weight']
                    mean_b = all_client_metrics[client_b]['mean_abs_weight']
                    
                    similarity = min(mean_a, mean_b) / (max(mean_a, mean_b) + 1e-10)
                    
                    # High similarity across multiple rounds = suspicious
                    if similarity > 0.95:
                        alert = {
                            'type': 'DISTRIBUTED_BACKDOOR',
                            'severity': 'MEDIUM',
                            'client_id': f'{client_a} & {client_b}',
                            'reason': f'Suspiciously similar weight patterns ({similarity:.2%} match)',
                            'confidence': 0.7,
                            'metrics': {
                                'similarity': float(similarity),
                                'mean_a': float(mean_a),
                                'mean_b': float(mean_b)
                            }
                        }
                        alerts.append(alert)
                        
                        # Log via structured logger
                        if structured_logger:
                            structured_logger.log_attack_detected(
                                attack_type='DISTRIBUTED_BACKDOOR',
                                client_id=f'{client_a}&{client_b}',
                                confidence=0.7,
                                evidence={'similarity': float(similarity)}
                            )
        
        return {
            'timestamp': datetime.now().isoformat(),
            'alerts': alerts,
            'analysis': analysis,
            'client_metrics': {k: v for k, v in all_client_metrics.items()}
        }
    
    def calculate_suspicion_score(self, client_id: str) -> float:
        """
        Calculate cumulative suspicion score over time
        Higher score = more likely to be malicious
        
        Range: 0.0 (benign) to 1.0 (definitely malicious)
        """
        if client_id not in self.update_history:
            return 0.0
        
        history = self.update_history[client_id]
        
        if not history:
            return 0.0
        
        # Trend analysis: is this client's anomaly score increasing?
        anomaly_scores = []
        
        for metrics in history:
            l2_norm = metrics['l2_norm']
            
            # Score based on deviation from "normal" (first update as baseline)
            if len(history) > 1:
                baseline_l2 = history[0]['l2_norm']
                deviation = abs(l2_norm - baseline_l2) / (baseline_l2 + 1e-10)
                anomaly_scores.append(min(1.0, deviation))
        
        if not anomaly_scores:
            return 0.0
        
        # Return increasing trend if suspicion growing over time
        recent_score = np.mean(anomaly_scores[-3:]) if len(anomaly_scores) >= 3 else anomaly_scores[-1]
        
        self.suspicion_scores[client_id] = recent_score
        
        return float(recent_score)


# ============================================
# EXAMPLE: Simulating Poisoning Attacks
# ============================================

def simulate_poisoning_attack(attack_type: str) -> Dict:
    """
    Simulate different poisoning attacks for testing
    """
    
    detector = PoisoningDetector()
    
    # Simulate 2 benign clients + 1 attacker
    benign_weights_1 = np.random.normal(0.1, 0.05, 1000).tolist()
    benign_weights_2 = np.random.normal(0.1, 0.05, 1000).tolist()
    
    if attack_type == "MODEL_REPLACEMENT":
        # Attacker: very large, scaled update
        attack_weights = np.random.normal(5.0, 2.0, 1000).tolist()  # 50x larger!
        attack_name = "Model Replacement (Scaled Attack)"
    
    elif attack_type == "CONSTRAIN_AND_SCALE":
        # Attacker: normal magnitude but tight distribution
        attack_weights = np.random.normal(0.1, 0.001, 1000).tolist()  # Very low variance!
        attack_name = "Constrain-and-Scale (Stealthy)"
    
    elif attack_type == "DBA":
        # Two attackers with correlated sub-patterns
        attack_weights = np.random.normal(0.09, 0.05, 1000).tolist()  # Almost identical to benign
        attack_name = "Distributed Backdoor (DBA)"
    
    else:
        attack_weights = benign_weights_1
        attack_name = "Normal"
    
    # Analyze all updates in one round
    metrics_1 = detector.analyze_update('client_1', benign_weights_1)
    metrics_2 = detector.analyze_update('client_2', benign_weights_2)
    metrics_atk = detector.analyze_update('attacker_client', attack_weights)
    
    all_metrics = {
        'client_1': metrics_1,
        'client_2': metrics_2,
        'attacker_client': metrics_atk
    }
    
    # Run detection
    detection_result = detector.detect_anomalies(all_metrics)
    
    # Calculate suspicion scores
    for client_id in all_metrics.keys():
        score = detector.calculate_suspicion_score(client_id)
        print(f"[{attack_name}] {client_id} suspicion score: {score:.2%}")
    
    return {
        'attack_type': attack_name,
        'detection_result': detection_result,
        'metrics': all_metrics
    }


if __name__ == '__main__':
    print("=" * 70)
    print("FEDERATED LEARNING - POISONING ATTACK DETECTION")
    print("=" * 70)
    
    # Test each attack type
    for attack in ['MODEL_REPLACEMENT', 'CONSTRAIN_AND_SCALE', 'DBA', 'NORMAL']:
        print(f"\n{'=' * 70}")
        print(f"Attack Type: {attack}")
        print('=' * 70)
        
        result = simulate_poisoning_attack(attack)
        
        # Display results
        if result['detection_result']['alerts']:
            print(f"\n ALERTS DETECTED:")
            for alert in result['detection_result']['alerts']:
                print(f"  - [{alert['severity']}] {alert['type']}")
                print(f"    Client: {alert['client_id']}")
                print(f"    Reason: {alert['reason']}")
                print(f"    Confidence: {alert['confidence']:.1%}")
        else:
            print(f"\n No anomalies detected")
        
        # Save detailed report
        with open(f'poisoning_report_{attack}.json', 'w') as f:
            json.dump(result, f, indent=2, default=str)
    
    print("\n Detection reports saved to poisoning_report_*.json")