#!/usr/bin/env python3
"""
test_security_attacks.py

PURPOSE:
- Master test suite that simulates ALL attacks from your SOTA paper
- Tests if our security detectors can catch each attack
- Generates comprehensive security reports
- Can run STANDALONE (locally) or in JENKINS PIPELINE

STRUCTURE:
1. Simulate each attack type
2. Pass attack data to detectors
3. Check if detector catches the attack
4. Generate test report (pass/fail)
5. Save results to JSON and HTML
"""

import sys
import os
import json
import numpy as np
from datetime import datetime
from pathlib import Path

# Add audit modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'audit'))

# Import all security detectors
try:
    from detect_poisoning import PoisoningDetector, simulate_poisoning_attack
    from detect_privacy_attacks import PrivacyAttackDetector, simulate_privacy_attack
    from detect_sybil_attacks import SybilDetector, simulate_sybil_attack
    print(" Successfully imported all security detectors")
except ImportError as e:
    print(f" Import error: {e}")
    print("   Make sure audit modules are in the 'audit/' directory")
    sys.exit(1)

class SecurityTestSuite:
    """
    Comprehensive security testing framework
    
    Tests each attack from SOTA paper:
    - Integrity Attacks: Poisoning, Backdoors, DBA
    - Privacy Attacks: Gradient Inversion, Membership Inference
    - Communication Attacks: Sybil
    """
    
    def __init__(self, output_dir='security_test_results'):
        self.output_dir = output_dir
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'skipped': 0
            }
        }
        
        # Create output directory
        Path(self.output_dir).mkdir(exist_ok=True)
    
    # ============================================
    # TEST GROUP 1: INTEGRITY ATTACKS (Poisoning)
    # ============================================
    
    def test_model_replacement_detection(self):
        """
        TEST: Can we detect Model Replacement attacks?
        
        Attack Description:
        - Attacker sends very large scaled update: L̃ = γ(X - G_t) + G_t
        - Tries to dominate aggregation with γ >> 1
        - Creates update norm 50x larger than normal
        
        Defense: Detect via L2 norm anomaly detection
        Expected: HIGH confidence detection
        """
        
        print("\n" + "="*70)
        print("TEST 1: MODEL REPLACEMENT ATTACK DETECTION")
        print("="*70)
        
        test_name = "model_replacement"
        detector = PoisoningDetector(threshold_std=2.5)
        
        # Create benign clients (normal weights)
        benign_client_1 = np.random.normal(0.1, 0.05, 1000)
        benign_client_2 = np.random.normal(0.1, 0.05, 1000)
        
        # Create attacker with scaled update (50x larger!)
        attack_weights = np.random.normal(5.0, 2.0, 1000)  # 50x larger magnitude
        
        print(f"\nSetup:")
        print(f"  Benign client 1 L2 norm: {np.linalg.norm(benign_client_1):.4f}")
        print(f"  Benign client 2 L2 norm: {np.linalg.norm(benign_client_2):.4f}")
        print(f"  Attacker L2 norm: {np.linalg.norm(attack_weights):.4f} TOO LARGE!")
        
        # Analyze updates
        metrics_1 = detector.analyze_update('benign_1', benign_client_1)
        metrics_2 = detector.analyze_update('benign_2', benign_client_2)
        metrics_atk = detector.analyze_update('attacker', attack_weights)
        
        all_metrics = {
            'benign_1': metrics_1,
            'benign_2': metrics_2,
            'attacker': metrics_atk
        }
        
        # Run detection
        detection_result = detector.detect_anomalies(all_metrics)
        
        # Check if we detected the attack
        poisoning_alerts = [a for a in detection_result['alerts'] 
                           if a['type'] == 'MODEL_REPLACEMENT']
        
        test_passed = len(poisoning_alerts) > 0 and any(
            'attacker' in a['client_id'] for a in poisoning_alerts
        )
        
        result = {
            'test_name': test_name,
            'description': 'Model Replacement (Scaled Attack)',
            'status': 'PASSED' if test_passed else 'FAILED',
            'expected': 'Detect attacker with anomalously large L2 norm',
            'actual': f'Found {len(poisoning_alerts)} MODEL_REPLACEMENT alerts',
            'alerts': poisoning_alerts,
            'metrics': all_metrics,
            'confidence': poisoning_alerts[0]['confidence'] if poisoning_alerts else 0.0
        }
        
        # Print result
        status_emoji = '' if test_passed else ''
        print(f"\n{status_emoji} Result: {result['status']}")
        print(f"   Expected: {result['expected']}")
        print(f"   Actual: {result['actual']}")
        if poisoning_alerts:
            print(f"   Confidence: {poisoning_alerts[0]['confidence']:.1%}")
        
        self.test_results['tests'][test_name] = result
        return test_passed
    
    def test_constrain_and_scale_detection(self):
        """
        TEST: Can we detect Constrain-and-Scale (stealthy) attacks?
        
        Attack Description:
        - Attacker trains backdoor with multi-objective loss
        - Constrains update to look benign (similar magnitude)
        - But direction and distribution are suspicious
        
        Defense: Detect via weight variance analysis
        Expected: MEDIUM confidence detection
        """
        
        print("\n" + "="*70)
        print("TEST 2: CONSTRAIN-AND-SCALE ATTACK DETECTION")
        print("="*70)
        
        test_name = "constrain_and_scale"
        detector = PoisoningDetector(threshold_std=2.5)
        
        # Benign clients: normal distribution
        benign_1 = np.random.normal(0.1, 0.05, 1000)
        benign_2 = np.random.normal(0.1, 0.05, 1000)
        
        # Attacker: tightly constrained (very low variance!)
        attack_weights = np.random.normal(0.1, 0.001, 1000)  # Same mean, tiny std!
        
        print(f"\nSetup:")
        print(f"  Benign client 1 std: {np.std(benign_1):.4f}")
        print(f"  Benign client 2 std: {np.std(benign_2):.4f}")
        print(f"  Attacker std: {np.std(attack_weights):.4f} TOO TIGHT!")
        
        # Analyze
        metrics_1 = detector.analyze_update('benign_1', benign_1)
        metrics_2 = detector.analyze_update('benign_2', benign_2)
        metrics_atk = detector.analyze_update('attacker', attack_weights)
        
        all_metrics = {
            'benign_1': metrics_1,
            'benign_2': metrics_2,
            'attacker': metrics_atk
        }
        
        # Detect
        detection_result = detector.detect_anomalies(all_metrics)
        
        # Check results
        stealthy_alerts = [a for a in detection_result['alerts'] 
                          if a['type'] == 'CONSTRAIN_AND_SCALE']
        
        test_passed = len(stealthy_alerts) > 0 and any(
            'attacker' in a['client_id'] for a in stealthy_alerts
        )
        
        result = {
            'test_name': test_name,
            'description': 'Constrain-and-Scale (Stealthy Attack)',
            'status': 'PASSED' if test_passed else 'FAILED',
            'expected': 'Detect unusually tight weight distribution',
            'actual': f'Found {len(stealthy_alerts)} CONSTRAIN_AND_SCALE alerts',
            'alerts': stealthy_alerts
        }
        
        status_emoji = '' if test_passed else ''
        print(f"\n{status_emoji} Result: {result['status']}")
        print(f"   Expected: {result['expected']}")
        print(f"   Actual: {result['actual']}")
        
        self.test_results['tests'][test_name] = result
        return test_passed
    
    def test_distributed_backdoor_detection(self):
        """
        TEST: Can we detect Distributed Backdoor Attacks (DBA)?
        
        Attack Description:
        - Multiple attackers coordinate (Sybils)
        - Each injects part of backdoor trigger: φ → {φ*_i}
        - Backdoor reconstructed only after aggregation
        
        Defense: Detect via multi-client correlation analysis
        Expected: MEDIUM confidence detection
        """
        
        print("\n" + "="*70)
        print("TEST 3: DISTRIBUTED BACKDOOR ATTACK DETECTION")
        print("="*70)
        
        test_name = "distributed_backdoor"
        detector = PoisoningDetector(threshold_std=2.5)
        
        # Benign clients
        benign_1 = np.random.normal(0.1, 0.05, 1000)
        
        # DBA: Two attackers with highly correlated updates
        base_pattern = np.random.normal(0.09, 0.05, 1000)
        attacker_1 = base_pattern + np.random.normal(0, 0.001, 1000)
        attacker_2 = base_pattern + np.random.normal(0, 0.001, 1000)
        
        print(f"\nSetup:")
        print(f"  Benign client correlation with self: 100%")
        print(f"  Attacker 1 vs Attacker 2 correlation: {np.corrcoef(attacker_1.flatten(), attacker_2.flatten())[0,1]:.1%} TOO SIMILAR!")
        
        # Analyze
        metrics_benign = detector.analyze_update('benign_1', benign_1)
        metrics_atk1 = detector.analyze_update('attacker_1', attacker_1)
        metrics_atk2 = detector.analyze_update('attacker_2', attacker_2)
        
        all_metrics = {
            'benign_1': metrics_benign,
            'attacker_1': metrics_atk1,
            'attacker_2': metrics_atk2
        }
        
        # Detect
        detection_result = detector.detect_anomalies(all_metrics)
        
        # Check results
        dba_alerts = [a for a in detection_result['alerts'] 
                     if a['type'] == 'DISTRIBUTED_BACKDOOR']
        
        test_passed = len(dba_alerts) > 0
        
        result = {
            'test_name': test_name,
            'description': 'Distributed Backdoor Attack (DBA)',
            'status': 'PASSED' if test_passed else 'FAILED',
            'expected': 'Detect suspiciously similar updates from multiple clients',
            'actual': f'Found {len(dba_alerts)} DISTRIBUTED_BACKDOOR alerts',
            'alerts': dba_alerts
        }
        
        status_emoji = '' if test_passed else ''
        print(f"\n{status_emoji} Result: {result['status']}")
        print(f"   Expected: {result['expected']}")
        print(f"   Actual: {result['actual']}")
        
        self.test_results['tests'][test_name] = result
        return test_passed
    
    # ============================================
    # TEST GROUP 2: PRIVACY ATTACKS
    # ============================================
    
    def test_gradient_inversion_detection(self):
        """
        TEST: Can we detect vulnerability to Gradient Inversion?
        
        Attack Description (DLG):
        - Attacker has gradients ∇L from public model query
        - Creates dummy data x', y' and computes ∇(ŷ_x')
        - Minimizes ||∇L - ∇(ŷ_x')|| to recover x' ≈ x
        
        Defense: Detect high-information gradients before transmission
        Expected: Measure invertibility risk
        """
        
        print("\n" + "="*70)
        print("TEST 4: GRADIENT INVERSION VULNERABILITY DETECTION")
        print("="*70)
        
        test_name = "gradient_inversion"
        detector = PrivacyAttackDetector(dp_epsilon=1.0, clipping_threshold=1.0)
        
        # Scenario 1: Large gradients (vulnerable!)
        vulnerable_gradients = np.random.normal(2.0, 0.5, 100)
        
        # Scenario 2: Small gradients (safer)
        safe_gradients = np.random.normal(0.1, 0.05, 100)
        
        print(f"\nSetup:")
        print(f"  Vulnerable gradient norm: {np.linalg.norm(vulnerable_gradients):.4f}")
        print(f"  Safe gradient norm: {np.linalg.norm(safe_gradients):.4f}")
        
        # Analyze vulnerable
        analysis_vuln = detector.analyze_gradient_invertibility(vulnerable_gradients)
        
        # Analyze safe
        analysis_safe = detector.analyze_gradient_invertibility(safe_gradients)
        
        # Test passed if vulnerable is detected as HIGH risk, safe as LOW
        test_passed = (
            analysis_vuln['inversion_risk_level'] == 'HIGH' and
            analysis_safe['inversion_risk_level'] == 'LOW'
        )
        
        result = {
            'test_name': test_name,
            'description': 'Gradient Inversion (DLG Attack)',
            'status': 'PASSED' if test_passed else 'FAILED',
            'expected': 'Vulnerable gradients = HIGH risk, Safe gradients = LOW risk',
            'actual': f'Vulnerable: {analysis_vuln["inversion_risk_level"]}, Safe: {analysis_safe["inversion_risk_level"]}',
            'vulnerable_risk': analysis_vuln['overall_inversion_risk'],
            'safe_risk': analysis_safe['overall_inversion_risk']
        }
        
        status_emoji = '' if test_passed else ''
        print(f"\n{status_emoji} Result: {result['status']}")
        print(f"   Expected: {result['expected']}")
        print(f"   Actual: {result['actual']}")
        print(f"   Vulnerable risk score: {analysis_vuln['overall_inversion_risk']:.1%}")
        print(f"   Safe risk score: {analysis_safe['overall_inversion_risk']:.1%}")
        
        self.test_results['tests'][test_name] = result
        return test_passed
    
    def test_membership_inference_detection(self):
        """
        TEST: Can we detect vulnerability to Membership Inference?
        
        Attack Description:
        - Attacker queries model with data point
        - If loss LOW → member, if loss HIGH → non-member
        - Large loss gap = easy to infer membership
        
        Defense: Detect large loss gaps
        Expected: HIGH risk if gap > 0.3, LOW risk if gap < 0.1
        """
        
        print("\n" + "="*70)
        print("TEST 5: MEMBERSHIP INFERENCE VULNERABILITY DETECTION")
        print("="*70)
        
        test_name = "membership_inference"
        detector = PrivacyAttackDetector(dp_epsilon=1.0)
        
        # Scenario 1: Large loss gap (vulnerable!)
        loss_in_vuln = 0.1
        loss_out_vuln = 0.5
        
        # Scenario 2: Small loss gap (safer, with DP)
        loss_in_safe = 0.3
        loss_out_safe = 0.35
        
        print(f"\nSetup:")
        print(f"  Vulnerable case - Loss gap: {loss_out_vuln - loss_in_vuln:.2f}")
        print(f"  Safe case (with DP) - Loss gap: {loss_out_safe - loss_in_safe:.2f}")
        
        # Analyze
        analysis_vuln = detector.detect_membership_inference_vulnerability(
            loss_in_vuln, loss_out_vuln, 0.3
        )
        analysis_safe = detector.detect_membership_inference_vulnerability(
            loss_in_safe, loss_out_safe, 0.3
        )
        
        # Test passed if vulnerable is HIGH risk, safe is LOW
        test_passed = (
            analysis_vuln['membership_inference_analysis']['risk_assessment'] == 'HIGH RISK' and
            analysis_safe['membership_inference_analysis']['risk_assessment'] == 'LOW RISK'
        )
        
        result = {
            'test_name': test_name,
            'description': 'Membership Inference Attack',
            'status': 'PASSED' if test_passed else 'FAILED',
            'expected': 'Vulnerable (large gap) = HIGH risk, Safe (small gap) = LOW risk',
            'actual': f'Vulnerable: {analysis_vuln["membership_inference_analysis"]["risk_assessment"]}, Safe: {analysis_safe["membership_inference_analysis"]["risk_assessment"]}',
            'vulnerable_gap': loss_out_vuln - loss_in_vuln,
            'safe_gap': loss_out_safe - loss_in_safe
        }
        
        status_emoji = '' if test_passed else ''
        print(f"\n{status_emoji} Result: {result['status']}")
        print(f"   Vulnerable risk: {analysis_vuln['membership_inference_analysis']['risk_assessment']}")
        print(f"   Safe risk: {analysis_safe['membership_inference_analysis']['risk_assessment']}")
        
        self.test_results['tests'][test_name] = result
        return test_passed
    
    # ============================================
    # TEST GROUP 3: COMMUNICATION ATTACKS (Sybils)
    # ============================================
    
    def test_sybil_detection(self):
        """
        TEST: Can we detect Sybil Attacks?
        
        Attack Description:
        - One attacker controls 3+ fake client identities
        - Submits highly correlated malicious updates
        - Amplifies attack power by voting multiple times
        
        Defense: FoolsGold - detect via update correlation
        Expected: Identify Sybil cluster with >95% confidence
        """
        
        print("\n" + "="*70)
        print("TEST 6: SYBIL ATTACK DETECTION")
        print("="*70)
        
        test_name = "sybil_attack"
        detector = SybilDetector(similarity_threshold=0.85)
        
        # Benign clients: diverse, independent updates
        benign_1 = np.random.normal(0.1, 0.05, 100)
        benign_2 = np.random.normal(0.1, 0.05, 100)
        
        # Sybils: same attacker, highly correlated updates
        base_attack = np.random.normal(2.0, 0.1, 100)
        sybil_1 = base_attack + np.random.normal(0, 0.01, 100)
        sybil_2 = base_attack + np.random.normal(0, 0.01, 100)
        sybil_3 = base_attack + np.random.normal(0, 0.01, 100)
        
        print(f"\nSetup:")
        print(f"  Benign 1 vs Benign 2 similarity: {detector.cosine_similarity(benign_1, benign_2):.1%}")
        print(f"  Sybil 1 vs Sybil 2 similarity: {detector.cosine_similarity(sybil_1, sybil_2):.1%} TOO HIGH!")
        print(f"  Sybil 2 vs Sybil 3 similarity: {detector.cosine_similarity(sybil_2, sybil_3):.1%} TOO HIGH!")
        
        # Record updates for round 1
        round_num = 1
        detector.record_update(round_num, 'benign_1', benign_1)
        detector.record_update(round_num, 'benign_2', benign_2)
        detector.record_update(round_num, 'sybil_1', sybil_1)
        detector.record_update(round_num, 'sybil_2', sybil_2)
        detector.record_update(round_num, 'sybil_3', sybil_3)
        
        # Detect Sybils
        analysis = detector.detect_sybils(round_num)
        
        # Test passed if we detect the Sybil group
        sybil_detected = len(analysis['sybil_groups']) > 0
        correct_group = any(
            set(group['suspected_sybils']) >= {'sybil_1', 'sybil_2', 'sybil_3'}
            for group in analysis['sybil_groups']
        )
        
        test_passed = sybil_detected and correct_group
        
        result = {
            'test_name': test_name,
            'description': 'Sybil Attack (Multiple Fake Identities)',
            'status': 'PASSED' if test_passed else 'FAILED',
            'expected': 'Detect Sybil cluster {sybil_1, sybil_2, sybil_3}',
            'actual': f'Found {len(analysis["sybil_groups"])} Sybil group(s)',
            'groups_detected': analysis['sybil_groups'],
            'client_scores': analysis['client_scores']
        }
        
        status_emoji = '' if test_passed else ''
        print(f"\n{status_emoji} Result: {result['status']}")
        if analysis['sybil_groups']:
            for group in analysis['sybil_groups']:
                print(f"   Detected group: {group['suspected_sybils']}")
                print(f"   Average similarity: {group['average_similarity']:.1%}")
        
        self.test_results['tests'][test_name] = result
        return test_passed
    
    # ============================================
    # RUN ALL TESTS
    # ============================================
    
    def run_all_tests(self):
        """Execute entire test suite"""
        
        print("\n" + "="*70)
        print("FEDERATED LEARNING - SECURITY TEST SUITE")
        print("="*70)
        print(f"Start time: {datetime.now().isoformat()}")
        
        tests = [
            self.test_model_replacement_detection,
            self.test_constrain_and_scale_detection,
            self.test_distributed_backdoor_detection,
            self.test_gradient_inversion_detection,
            self.test_membership_inference_detection,
            self.test_sybil_detection,
        ]
        
        results = []
        for test_func in tests:
            try:
                passed = test_func()
                results.append(passed)
            except Exception as e:
                print(f"\n Test {test_func.__name__} crashed: {e}")
                results.append(False)
        
        # Summary
        self.test_results['summary']['total_tests'] = len(tests)
        self.test_results['summary']['passed'] = sum(results)
        self.test_results['summary']['failed'] = len(results) - sum(results)
        
        self._print_summary(results)
        self._save_results()
        
        return all(results)
    
    def _print_summary(self, results):
        """Print test summary"""
        
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        
        total = self.test_results['summary']['total_tests']
        passed = self.test_results['summary']['passed']
        failed = self.test_results['summary']['failed']
        
        print(f"\nTotal Tests: {total}")
        print(f" Passed: {passed}")
        print(f" Failed: {failed}")
        print(f"Success Rate: {passed/total*100:.1f}%")
        
        if failed == 0:
            print(f"\n ALL TESTS PASSED! Security suite is working correctly.")
        else:
            print(f"\n {failed} test(s) failed. Review above for details.")
    
    def _save_results(self):
        """Save test results to JSON and HTML"""
        
        # JSON report
        json_path = os.path.join(self.output_dir, 'test_results.json')
        with open(json_path, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        print(f"\n Results saved to: {json_path}")
        
        # HTML report
        self._generate_html_report()
    
    def _generate_html_report(self):
        """Generate HTML report"""
        
        html_path = os.path.join(self.output_dir, 'test_results.html')
        
        summary = self.test_results['summary']
        tests = self.test_results['tests']
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>FL Security Test Report</title>
    <style>
        body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        .header {{ background: #4ecdc4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ background: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #4ecdc4; }}
        .passed {{ border-left-color: #51cf66; }}
        .failed {{ border-left-color: #ff6b6b; }}
        .test {{ background: white; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .test-header {{ font-weight: bold; font-size: 16px; margin-bottom: 10px; }}
        .status-passed {{ color: #51cf66; }}
        .status-failed {{ color: #ff6b6b; }}
        .metric {{ display: inline-block; background: #e8f5e9; padding: 8px 12px; margin: 5px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> FL Security Test Report</h1>
            <p>Generated: {datetime.now().isoformat()}</p>
        </div>
        
        <div class="summary passed">
            <strong>Summary</strong><br>
            Total Tests: {summary['total_tests']}<br>
            Passed: {summary['passed']}<br>
            Failed: {summary['failed']}<br>
            Success Rate: {summary['passed']/summary['total_tests']*100:.1f}%
        </div>
        
        <h2>Test Results</h2>
"""
        
        for test_name, test_data in tests.items():
            status_class = 'status-passed' if test_data['status'] == 'PASSED' else 'status-failed'
            status_emoji = '' if test_data['status'] == 'PASSED' else ''
            
            html += f"""
        <div class="test">
            <div class="test-header">
                <span class="{status_class}">{status_emoji} {test_data['description']}</span>
            </div>
            <p><strong>Expected:</strong> {test_data['expected']}</p>
            <p><strong>Actual:</strong> {test_data['actual']}</p>
"""
            
            if 'confidence' in test_data:
                html += f'<div class="metric">Confidence: {test_data["confidence"]:.1%}</div>'
            
            html += "</div>"
        
        html += """
    </div>
</body>
</html>
"""
        
        with open(html_path, 'w') as f:
            f.write(html)
        
        print(f" HTML report saved to: {html_path}")


if __name__ == '__main__':
    # Run test suite
    suite = SecurityTestSuite(output_dir='security_test_results')
    all_passed = suite.run_all_tests()
    
    # Exit with appropriate code for CI/CD
    sys.exit(0 if all_passed else 1)