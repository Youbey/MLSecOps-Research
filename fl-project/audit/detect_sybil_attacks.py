"""
Detect Sybil Attacks in FL

Attack:
- One attacker controls multiple fake client identities
- Submits coordinated malicious updates to amplify attack power
- Can perform model poisoning, label flipping, backdoors with amplified effect

Defense (FoolsGold):
- Detect Sybils by measuring update similarity across rounds
- Clients with consistently high similarity get reduced learning rates
- Doesn't require explicit client identification
"""

import numpy as np
import json
from typing import Dict, List, Tuple
from datetime import datetime
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SybilDetector")

class SybilDetector:
    """
    Detects Sybil attacks using gradient similarity analysis
    
    Implements FoolsGold algorithm:
    - Track cosine similarity of updates across rounds
    - Clients with high correlation across rounds = likely Sybils
    - Penalize correlated clients with reduced weighting
    """
    
    def __init__(self, history_window: int = 10, similarity_threshold: float = 0.85):
        """
        Args:
            history_window: Number of rounds to track
            similarity_threshold: Cosine similarity threshold for suspicion
        """
        self.history_window = history_window
        self.similarity_threshold = similarity_threshold
        self.update_history = defaultdict(list)  # client_id -> list of updates
        self.sybil_scores = {}  # client_id -> suspicion score
    
    def cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        Calculate cosine similarity between two vectors
        Range: -1 (opposite) to 1 (identical)
        """
        vec1 = np.array(vec1, dtype=np.float32).flatten()
        vec2 = np.array(vec2, dtype=np.float32).flatten()
        
        # Normalize
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        vec1_norm = vec1 / norm1
        vec2_norm = vec2 / norm2
        
        # Cosine similarity
        similarity = np.dot(vec1_norm, vec2_norm)
        
        return float(np.clip(similarity, -1.0, 1.0))
    
    def record_update(self, round_number: int, client_id: str, weights: List):
        """
        Record a client's update for a given round
        """
        self.update_history[client_id].append({
            'round': round_number,
            'weights': np.array(weights, dtype=np.float32),
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only recent history
        if len(self.update_history[client_id]) > self.history_window:
            self.update_history[client_id].pop(0)
    
    def detect_sybils(self, round_number: int) -> Dict:
        """
        Detect Sybil clients by analyzing update similarity
        
        Logic:
        1. Calculate pairwise similarity between all clients
        2. If client_A and client_B are consistently similar → likely same attacker
        3. Form clusters of correlated clients
        4. Penalize entire clusters
        """
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'round': round_number,
            'sybil_groups': [],
            'client_scores': {},
            'recommendations': []
        }
        
        # Get latest updates from all clients
        latest_updates = {}
        for client_id, history in self.update_history.items():
            if history:  # If client has updates
                latest_updates[client_id] = history[-1]['weights']
        
        if len(latest_updates) < 2:
            return analysis  # Need at least 2 clients to detect Sybils
        
        # ==========================================
        # STEP 1: Calculate Pairwise Similarities
        # ==========================================
        
        client_ids = list(latest_updates.keys())
        similarity_matrix = np.zeros((len(client_ids), len(client_ids)))
        
        for i, client_a in enumerate(client_ids):
            for j, client_b in enumerate(client_ids):
                if i < j:
                    sim = self.cosine_similarity(
                        latest_updates[client_a],
                        latest_updates[client_b]
                    )
                    similarity_matrix[i, j] = sim
                    similarity_matrix[j, i] = sim
        
        analysis['similarity_matrix'] = similarity_matrix.tolist()
        
        # ==========================================
        # STEP 2: Identify Sybil Clusters
        # ==========================================
        
        # Find groups of highly similar clients
        detected_groups = []
        used_clients = set()
        
        for i, client_a in enumerate(client_ids):
            if client_a in used_clients:
                continue
            
            # Find all clients similar to client_a
            similar_clients = [client_a]
            
            for j, client_b in enumerate(client_ids):
                if i != j and client_b not in used_clients:
                    sim = similarity_matrix[i, j]
                    if sim > self.similarity_threshold:
                        similar_clients.append(client_b)
                        used_clients.add(client_b)
            
            # If group has more than 1 client, it's suspicious
            if len(similar_clients) > 1:
                detected_groups.append({
                    'suspected_sybils': similar_clients,
                    'group_size': len(similar_clients),
                    'average_similarity': float(np.mean([
                        similarity_matrix[client_ids.index(c1), client_ids.index(c2)]
                        for c1 in similar_clients for c2 in similar_clients
                        if c1 != c2
                    ]) if len(similar_clients) > 1 else 0)
                })
            
            used_clients.add(client_a)
        
        analysis['sybil_groups'] = detected_groups
        
        # ==========================================
        # STEP 3: Calculate Suspicion Scores
        # ==========================================
        
        for client_id in client_ids:
            idx = client_ids.index(client_id)
            
            # Calculate average similarity to other clients
            similarities = []
            for j, other_id in enumerate(client_ids):
                if idx != j:
                    similarities.append(similarity_matrix[idx, j])
            
            avg_similarity = np.mean(similarities) if similarities else 0.0
            
            # Suspicion increases with similarity to other clients
            suspicion_score = min(1.0, max(0.0, (avg_similarity - 0.5) * 2.0))
            
            self.sybil_scores[client_id] = suspicion_score
            
            analysis['client_scores'][client_id] = {
                'suspicion_score': float(suspicion_score),
                'average_similarity': float(avg_similarity),
                'max_similarity': float(max(similarities)) if similarities else 0.0,
                'severity': (
                    'HIGH' if suspicion_score > 0.7 else
                    'MEDIUM' if suspicion_score > 0.4 else
                    'LOW'
                )
            }
        
        # ==========================================
        # STEP 4: Recommendations
        # ==========================================
        
        if detected_groups:
            analysis['recommendations'].append(
                f" SYBIL ATTACK DETECTED: Found {len(detected_groups)} suspicious group(s)"
            )
            
            for group in detected_groups:
                analysis['recommendations'].append(
                    f"  - Suspected Sybils: {group['suspected_sybils']} "
                    f"(similarity: {group['average_similarity']:.1%})"
                )
            
            analysis['recommendations'].append(
                "  Mitigation: Apply FoolsGold to reduce weights of correlated clients"
            )
        
        return analysis
    
    def apply_foolsgold_weighting(self, analysis: Dict) -> Dict:
        """
        Apply FoolsGold algorithm to adjust client weights
        
        High similarity → reduced weight
        Low similarity → normal/increased weight
        """
        
        weighting = {
            'timestamp': datetime.now().isoformat(),
            'client_weights': {}
        }
        
        for client_id, score in analysis['client_scores'].items():
            suspicion = score['suspicion_score']
            
            # FoolsGold: reduce weight proportional to suspicion
            # Normal weight = 1.0, Suspicious weight = 0.0
            foolsgold_weight = 1.0 - suspicion
            
            weighting['client_weights'][client_id] = {
                'original_weight': 1.0,
                'foolsgold_weight': float(foolsgold_weight),
                'reduction_ratio': float(suspicion),
                'action': (
                    'EXCLUDE' if foolsgold_weight < 0.1 else
                    'PENALIZE' if foolsgold_weight < 0.5 else
                    'NORMAL'
                )
            }
        
        return weighting
    
    def detect_sybil_behaviors(self, client_updates: Dict[str, Dict]) -> Dict:
        """
        Additional heuristics to detect Sybil-specific behaviors
        """
        
        behaviors = {
            'timestamp': datetime.now().isoformat(),
            'suspicious_behaviors': []
        }
        
        # ==========================================
        # Behavior 1: Same IP Address
        # ==========================================
        ip_addresses = defaultdict(list)
        for client_id, info in client_updates.items():
            ip = info.get('ip_address', 'unknown')
            ip_addresses[ip].append(client_id)
        
        for ip, clients in ip_addresses.items():
            if len(clients) > 1:
                behaviors['suspicious_behaviors'].append({
                    'type': 'SAME_IP_ADDRESS',
                    'severity': 'HIGH',
                    'clients': clients,
                    'evidence': f'{len(clients)} clients from same IP: {ip}',
                    'confidence': 0.9
                })
        
        # ==========================================
        # Behavior 2: Synchronized Participation
        # ==========================================
        # Sybils tend to join/leave together
        # This would require tracking participation history
        
        # ==========================================
        # Behavior 3: Identical Device Fingerprints
        # ==========================================
        # Sybils may share hardware signatures
        device_fingerprints = defaultdict(list)
        for client_id, info in client_updates.items():
            fp = info.get('device_fingerprint', 'unknown')
            device_fingerprints[fp].append(client_id)
        
        for fp, clients in device_fingerprints.items():
            if len(clients) > 1:
                behaviors['suspicious_behaviors'].append({
                    'type': 'IDENTICAL_DEVICE_FINGERPRINT',
                    'severity': 'MEDIUM',
                    'clients': clients,
                    'evidence': f'{len(clients)} clients with identical fingerprint',
                    'confidence': 0.7
                })
        
        return behaviors


# ============================================
# EXAMPLE: Simulating Sybil Attacks
# ============================================

def simulate_sybil_attack():
    """
    Simulate a Sybil attack scenario
    """
    
    detector = SybilDetector(history_window=10, similarity_threshold=0.85)
    
    print(f"\n{'=' * 70}")
    print("SYBIL ATTACK SIMULATION")
    print('=' * 70)
    
    # Simulate multiple rounds
    for round_num in range(1, 6):
        print(f"\n--- Round {round_num} ---")
        
        # 2 benign clients: random, independent updates
        benign1 = np.random.normal(0.1, 0.05, 100)
        benign2 = np.random.normal(0.1, 0.05, 100)
        
        # 3 Sybils (same attacker): highly correlated updates
        base_attack = np.random.normal(2.0, 0.1, 100)
        sybil1 = base_attack + np.random.normal(0, 0.01, 100)  # Tiny variation
        sybil2 = base_attack + np.random.normal(0, 0.01, 100)  # Tiny variation
        sybil3 = base_attack + np.random.normal(0, 0.01, 100)  # Tiny variation
        
        # Record updates
        detector.record_update(round_num, 'client_benign_1', benign1)
        detector.record_update(round_num, 'client_benign_2', benign2)
        detector.record_update(round_num, 'sybil_1', sybil1)
        detector.record_update(round_num, 'sybil_2', sybil2)
        detector.record_update(round_num, 'sybil_3', sybil3)
        
        # Detect Sybils
        analysis = detector.detect_sybils(round_num)
        
        # Show results
        if analysis['sybil_groups']:
            print(f"\n SYBIL GROUP DETECTED:")
            for group in analysis['sybil_groups']:
                print(f"   Clients: {group['suspected_sybils']}")
                print(f"   Similarity: {group['average_similarity']:.1%}")
        
        # Show suspicion scores
        print(f"\n Client Suspicion Scores:")
        for client_id, score_info in analysis['client_scores'].items():
            print(f"   {client_id}: {score_info['suspicion_score']:.1%} ({score_info['severity']})")
        
        # Apply FoolsGold
        foolsgold = detector.apply_foolsgold_weighting(analysis)
        
        print(f"\n FoolsGold Adjustments:")
        for client_id, weight_info in foolsgold['client_weights'].items():
            print(f"   {client_id}: weight {weight_info['original_weight']:.1f} → "
                  f"{weight_info['foolsgold_weight']:.1f} ({weight_info['action']})")
    
    # Final report
    print(f"\n{'=' * 70}")
    print("FINAL SUMMARY")
    print('=' * 70)
    
    for client_id, score in detector.sybil_scores.items():
        verdict = 'SYBIL (BLOCK)' if score > 0.7 else 'LIKELY SYBIL (PENALIZE)' if score > 0.4 else 'BENIGN'
        print(f"{client_id}: {verdict} (score: {score:.1%})")


if __name__ == '__main__':
    print("=" * 70)
    print("FEDERATED LEARNING - SYBIL ATTACK DETECTION")
    print("=" * 70)
    
    simulate_sybil_attack()
    
    print("\n Sybil detection analysis complete")