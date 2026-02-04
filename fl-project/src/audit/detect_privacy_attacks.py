"""
Detect Privacy Attacks in FL

Attack Types:
1. Gradient Inversion (DLG) - Reconstructing training data from gradients
2. Membership Inference - Determining if data was in training set
3. Property Inference - Inferring aggregate properties of dataset

Defense:
- Differential Privacy (DP) - Add noise to gradients
- Secure Aggregation - Hide individual updates
- Gradient Clipping - Limit gradient magnitude
"""

import numpy as np
import json
from typing import Dict, List, Tuple
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PrivacyDetector")

class PrivacyAttackDetector:
    """
    Detects privacy attacks by monitoring gradient characteristics
    that could enable inversion or inference
    """
    
    def __init__(self, dp_epsilon: float = 1.0, clipping_threshold: float = 1.0):
        """
        Args:
            dp_epsilon: Differential privacy budget (lower = more private, but noisier)
            clipping_threshold: Maximum gradient norm allowed
        """
        self.dp_epsilon = dp_epsilon
        self.clipping_threshold = clipping_threshold
        self.gradient_history = {}
    
    def analyze_gradient_invertibility(self, gradients: np.ndarray, 
                                     label_gradients: np.ndarray = None) -> Dict:
        """
        Analyze how easy it is to invert gradients to recover training data
        
        DLG Attack works by:
        1. Attacker has access to gradients ∇L
        2. Creates dummy input x' and label y'
        3. Minimizes distance between ∇L and ∇(ŷ_x')
        4. When distance minimized, x' ≈ x (original data)
        
        Defense: Add noise, clip gradients, compress
        """
        gradients = np.array(gradients, dtype=np.float32)
        
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'invertibility_indicators': {}
        }
        
        # ==========================================
        # Indicator 1: Gradient Magnitude (Information Content)
        # ==========================================
        # Large gradients = more information = easier to invert
        grad_norm = np.linalg.norm(gradients)
        grad_mean = np.mean(np.abs(gradients))
        grad_max = np.max(np.abs(gradients))
        
        metrics['invertibility_indicators']['gradient_norm'] = float(grad_norm)
        metrics['invertibility_indicators']['gradient_mean'] = float(grad_mean)
        metrics['invertibility_indicators']['gradient_max'] = float(grad_max)
        
        # Risk score: how much information is exposed?
        # Normalized to [0, 1] where 1 = high risk
        gradient_risk = min(1.0, grad_norm / 100.0)  # Assume >100 is very high risk
        metrics['invertibility_indicators']['gradient_information_risk'] = float(gradient_risk)
        
        # ==========================================
        # Indicator 2: Gradient Sparsity
        # ==========================================
        # Sparse gradients = less information = harder to invert
        num_zero_gradients = np.sum(np.abs(gradients) < 1e-6)
        sparsity_ratio = num_zero_gradients / len(gradients.flatten())
        
        metrics['invertibility_indicators']['sparsity_ratio'] = float(sparsity_ratio)
        
        # Higher sparsity = better (less invertible)
        sparsity_benefit = min(1.0, sparsity_ratio * 10)
        metrics['invertibility_indicators']['sparsity_protection_benefit'] = float(sparsity_benefit)
        
        # ==========================================
        # Indicator 3: Gradient Similarity Patterns
        # ==========================================
        # If gradients follow predictable patterns = higher inversion risk
        # Calculate entropy as measure of randomness
        
        # Quantize gradients to detect patterns
        quantized = np.digitize(gradients.flatten(), bins=10)
        
        # Shannon entropy (higher = more random = safer)
        unique, counts = np.unique(quantized, return_counts=True)
        probabilities = counts / len(quantized)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        
        max_entropy = np.log2(len(unique))  # Maximum possible entropy
        entropy_ratio = entropy / (max_entropy + 1e-10)
        
        metrics['invertibility_indicators']['entropy_ratio'] = float(entropy_ratio)
        
        # ==========================================
        # Indicator 4: Batch Size Leakage
        # ==========================================
        # Small batch size = easier to invert (less aggregation)
        # Check if gradient norms indicate small batches
        
        metrics['invertibility_indicators']['batch_size_leakage'] = {
            'risk': 'small batch detected' if grad_max > 1.0 else 'large batch (safer)',
            'evidence': float(grad_max)
        }
        
        # ==========================================
        # OVERALL INVERTIBILITY RISK SCORE
        # ==========================================
        # Combine indicators into single risk score
        
        inversion_risk = (
            0.4 * gradient_risk +           # Gradient magnitude
            0.3 * (1 - sparsity_benefit) +  # Lack of sparsity
            0.3 * (1 - entropy_ratio)       # Predictable patterns
        )
        
        metrics['overall_inversion_risk'] = float(inversion_risk)
        metrics['inversion_risk_level'] = (
            'HIGH' if inversion_risk > 0.7 else
            'MEDIUM' if inversion_risk > 0.4 else
            'LOW'
        )
        
        return metrics
    
    def detect_membership_inference_vulnerability(self, model_loss_in: float,
                                                  model_loss_out: float,
                                                  population_loss: float) -> Dict:
        """
        Detect vulnerability to Membership Inference attacks
        
        Attack: Attacker queries model with data point
        - If loss is LOW → data was likely in training set (MEMBER)
        - If loss is HIGH → data was likely NOT in training set (NON-MEMBER)
        
        Defense: DP smooths loss distribution, making this harder
        """
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'membership_inference_analysis': {}
        }
        
        # ==========================================
        # Indicator 1: Loss Gap
        # ==========================================
        # Large gap between member/non-member loss = vulnerable
        loss_gap = model_loss_in - model_loss_out
        
        analysis['membership_inference_analysis']['loss_in_training'] = float(model_loss_in)
        analysis['membership_inference_analysis']['loss_out_training'] = float(model_loss_out)
        analysis['membership_inference_analysis']['loss_gap'] = float(loss_gap)
        
        # Higher gap = higher risk of membership inference
        membership_risk = min(1.0, abs(loss_gap) / 0.5)  # Normalize by typical gap
        analysis['membership_inference_analysis']['membership_inference_risk'] = float(membership_risk)
        
        # ==========================================
        # Indicator 2: Privacy Impact
        # ==========================================
        # How much more likely is member vs non-member?
        # Using simple odds ratio
        
        if model_loss_out > 0:
            odds_ratio = model_loss_in / model_loss_out
            analysis['membership_inference_analysis']['odds_ratio'] = float(odds_ratio)
            
            # If odds ratio is close to 1, membership is hard to infer
            membership_difficulty = 1.0 / (1.0 + abs(odds_ratio - 1.0))
            analysis['membership_inference_analysis']['privacy_strength'] = float(membership_difficulty)
        
        # ==========================================
        # Indicator 3: Differential Privacy Evaluation
        # ==========================================
        # With DP, loss gap should be reduced
        analysis['membership_inference_analysis']['recommended_epsilon'] = 1.0  # GDPR-compliant
        analysis['membership_inference_analysis']['risk_assessment'] = (
            'HIGH RISK' if membership_risk > 0.7 else
            'MEDIUM RISK' if membership_risk > 0.4 else
            'LOW RISK'
        )
        
        return analysis
    
    def evaluate_differential_privacy_protection(self, gradients: np.ndarray,
                                                clipping_norm: float,
                                                noise_scale: float = None) -> Dict:
        """
        Evaluate how well Differential Privacy protects the gradients
        """
        gradients = np.array(gradients, dtype=np.float32)
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'dp_protection': {}
        }
        
        # ==========================================
        # Defense 1: Gradient Clipping
        # ==========================================
        grad_norm = np.linalg.norm(gradients)
        clipping_applied = grad_norm > clipping_norm
        
        analysis['dp_protection']['gradient_clipping'] = {
            'applied': bool(clipping_applied),
            'gradient_norm': float(grad_norm),
            'clipping_threshold': float(clipping_norm),
            'clipping_ratio': float(min(1.0, grad_norm / clipping_norm))
        }
        
        # ==========================================
        # Defense 2: Noise Addition
        # ==========================================
        if noise_scale is None:
            noise_scale = clipping_norm * 2.0  # Conservative default
        
        # Estimate noise that would be added
        gaussian_noise = np.random.normal(0, noise_scale, gradients.shape)
        noise_ratio = np.linalg.norm(gaussian_noise) / (np.linalg.norm(gradients) + 1e-10)
        
        analysis['dp_protection']['gaussian_noise'] = {
            'noise_scale': float(noise_scale),
            'estimated_noise_ratio': float(noise_ratio),
            'privacy_budget_epsilon': self.dp_epsilon,
            'privacy_budget_delta': 1e-5
        }
        
        # ==========================================
        # Defense 3: Secure Aggregation
        # ==========================================
        # Secure aggregation hides individual gradients
        analysis['dp_protection']['secure_aggregation'] = {
            'enabled': True,  # Assume in production
            'effectiveness': 'Prevents server from seeing individual updates',
            'trade_off': 'Adds computational overhead'
        }
        
        # ==========================================
        # Overall Privacy Score
        # ==========================================
        clipping_score = 0.5 if clipping_applied else 0.0
        noise_score = 0.3 * (1 - min(1.0, 1.0 / noise_ratio))
        secagg_score = 0.2  # Always on in production
        
        overall_privacy = clipping_score + noise_score + secagg_score
        
        analysis['overall_privacy_score'] = float(overall_privacy)
        analysis['privacy_level'] = (
            'STRONG' if overall_privacy > 0.8 else
            'MODERATE' if overall_privacy > 0.5 else
            'WEAK'
        )
        
        return analysis


# ============================================
# EXAMPLE: Simulating Privacy Attacks
# ============================================

def simulate_privacy_attack(attack_type: str):
    """
    Simulate different privacy attacks
    """
    
    detector = PrivacyAttackDetector(dp_epsilon=1.0, clipping_threshold=1.0)
    
    print(f"\n{'=' * 70}")
    print(f"Privacy Attack: {attack_type}")
    print('=' * 70)
    
    if attack_type == "GRADIENT_INVERSION":
        # Attacker: Large, information-rich gradients
        gradients = np.random.normal(2.0, 0.5, 100)  # Large gradients = vulnerable!
        print("\n SCENARIO: Large gradients exposed to network")
        print("   Attacker performs DLG attack to reconstruct training data")
        
        result = detector.analyze_gradient_invertibility(gradients)
        
        print(f"\n Invertibility Analysis:")
        print(f"   Risk Level: {result['inversion_risk_level']}")
        print(f"   Risk Score: {result['overall_inversion_risk']:.1%}")
        print(f"   Gradient Norm: {result['invertibility_indicators']['gradient_norm']:.4f}")
        print(f"   Sparsity: {result['invertibility_indicators']['sparsity_ratio']:.1%}")
        
        return result
    
    elif attack_type == "MEMBERSHIP_INFERENCE":
        # Attacker: Model leaks membership info via loss
        loss_in = 0.1   # Low loss for members
        loss_out = 0.5  # High loss for non-members
        pop_loss = 0.3
        
        print("\n SCENARIO: Loss function reveals membership")
        print(f"   Loss (member data): {loss_in}")
        print(f"   Loss (non-member): {loss_out}")
        
        result = detector.detect_membership_inference_vulnerability(loss_in, loss_out, pop_loss)
        
        print(f"\n Membership Inference Analysis:")
        print(f"   Risk Level: {result['membership_inference_analysis']['risk_assessment']}")
        print(f"   Risk Score: {result['membership_inference_analysis']['membership_inference_risk']:.1%}")
        print(f"   Loss Gap: {result['membership_inference_analysis']['loss_gap']:.4f}")
        
        return result
    
    elif attack_type == "WITH_DIFFERENTIAL_PRIVACY":
        # Defense: Apply DP to gradients
        gradients = np.random.normal(0.1, 0.05, 100)  # Small gradients with DP
        
        print("\n SCENARIO: Differential Privacy Applied")
        print("   - Gradients clipped to norm 1.0")
        print("   - Gaussian noise added (scale=2.0)")
        print("   - Secure aggregation enabled")
        
        result = detector.evaluate_differential_privacy_protection(
            gradients,
            clipping_norm=1.0,
            noise_scale=2.0
        )
        
        print(f"\n Privacy Protection Analysis:")
        print(f"   Privacy Level: {result['privacy_level']}")
        print(f"   Privacy Score: {result['overall_privacy_score']:.1%}")
        print(f"   Clipping Applied: {result['dp_protection']['gradient_clipping']['applied']}")
        
        return result


if __name__ == '__main__':
    print("=" * 70)
    print("FEDERATED LEARNING - PRIVACY ATTACK DETECTION")
    print("=" * 70)
    
    # Simulate each privacy attack
    for attack in ['GRADIENT_INVERSION', 'MEMBERSHIP_INFERENCE', 'WITH_DIFFERENTIAL_PRIVACY']:
        result = simulate_privacy_attack(attack)
        
        # Save report
        with open(f'privacy_report_{attack}.json', 'w') as f:
            json.dump(result, f, indent=2, default=str)
    
    print("\n Privacy reports saved to privacy_report_*.json")