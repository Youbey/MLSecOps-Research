"""
Control script that orchestrates FL training rounds
Signals clients, waits for updates, triggers aggregation, and saves reports
"""

import requests
import json
import time
import sys
import argparse
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("CONTROLLER")

SERVER_URL = "http://localhost:5000"

class FLController:
    def __init__(self, server_url=SERVER_URL):
        self.server_url = server_url
    
    def check_server_health(self):
        """Check if server is running"""
        try:
            response = requests.get(f'{self.server_url}/health', timeout=2)
            data = response.json()
            logger.info(f"Server healthy (round {data['round']}, {data['clients']} clients)")
            return True
        except Exception as e:
            logger.error(f"Server is not responding: {e}")
            return False
    
    def get_status(self):
        """Get detailed server status"""
        try:
            response = requests.get(f'{self.server_url}/status')
            return response.json()
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return None
    
    def print_status(self):
        """Pretty print server status"""
        status = self.get_status()
        if not status:
            return
        
        print("\n" + "="*70)
        print(f"FEDERATION STATUS - Round {status['round']}")
        print("="*70)
        
        print(f"\nClients ({len(status['clients'])} total):")
        for client_id, state in status['clients'].items():
            print(f"  {client_id}")
            print(f"    Updates: {state['updates_received']} received, {state['updates_accepted']} accepted, {state['updates_rejected']} rejected")
            if state['last_metrics']:
                metrics = state['last_metrics']
                print(f"    Metrics: loss={metrics.get('loss', 0):.4f}, accuracy={metrics.get('accuracy', 0):.4f}")
            if state['attacks_detected']:
                print(f"    ⚠️  ATTACKS DETECTED: {len(state['attacks_detected'])}")
                # Show attack types if available
                if 'attack_types' in state:
                    attack_summary = []
                    for attack_type, count in state['attack_types'].items():
                        if count > 0:
                            attack_summary.append(f"{attack_type}({count})")
                    if attack_summary:
                        print(f"    Attack Types: {', '.join(attack_summary)}")
        
        print(f"\nPending updates: {status['pending_updates']}")
        print(f"Attacks detected this round: {status['attacks_detected_this_round']}")
        print(f"Total attacks detected: {status['total_attacks_detected']}")
        
        if status['attacks_detected_this_round'] > 0:
            try:
                sec_status = requests.get(f'{self.server_url}/security/status').json()
                print(f"\n🔴 Recent Attack Details:")
                
                # Show attack type summary if available
                if 'attack_types_summary' in sec_status:
                    print(f"\nAttack Types Summary:")
                    for attack_type, count in sec_status['attack_types_summary'].items():
                        print(f"  - {attack_type}: {count} times")
                
                # Show recent attacks
                for attack in sec_status.get('recent_attacks', []):
                    if attack['round'] == status['round']:
                        client_id = attack.get('client_id', 'unknown')
                        confidence = attack.get('overall_confidence', 0)
                        print(f"\n  Round {attack['round']}: {client_id} (confidence={confidence:.2f})")
                        
                        # Show detailed attack types
                        if 'attacks_detected' in attack:
                            for det in attack['attacks_detected']:
                                attack_type = det.get('type', 'UNKNOWN')
                                det_conf = det.get('confidence', 0)
                                print(f"    └─ {attack_type} (confidence={det_conf:.2f})")
                                
                                # Show detection details if available
                                if 'details' in det and det['details']:
                                    details = det['details']
                                    if 'detection_methods' in details:
                                        print(f"       Methods: {', '.join(details['detection_methods'])}")
                                    if 'detection' in details:
                                        print(f"       {details['detection']}")
            except Exception as e:
                logger.error(f"Error getting security status: {e}")
    
    def signal_training_round(self):
        """Signal server to trigger training round"""
        try:
            response = requests.post(
                f'{self.server_url}/trigger_round',
                timeout=5
            )
            if response.status_code == 200:
                logger.info("✓ Training round triggered at server")
                return True
        except Exception as e:
            logger.error(f"Error triggering round: {e}")
        return False
    
    def wait_for_updates(self, timeout=60):
        """Wait for clients to submit updates"""
        logger.info(f"Waiting {timeout}s for client updates...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_status()
            if status and status['pending_updates']:
                logger.info(f"Received {len(status['pending_updates'])} updates from clients")
                return True
            
            time.sleep(2)
        
        logger.warning(f"Timeout waiting for updates")
        return False
    
    def trigger_aggregation(self):
        """Trigger model aggregation at the server"""
        logger.info("Aggregation complete (clients' updates have been processed)")
        return True
    
    def reset_round(self):
        """Reset the server's round state (for testing between attack scenarios)"""
        try:
            response = requests.post(
                f'{self.server_url}/reset_round',
                timeout=5
            )
            if response.status_code == 200:
                logger.info("✓ Server round state reset")
                return True
            else:
                logger.error(f"Failed to reset round: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error resetting round: {e}")
            return False
    
    def interactive_monitor(self, interval=10):
        """Continuous monitoring mode"""
        logger.info("Starting interactive monitoring (Ctrl+C to exit)")
        try:
            while True:
                self.print_status()
                logger.info(f"Next update in {interval}s...")
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
    
    def run_training_sequence(self, num_rounds=5, wait_time=60):
        """
        Full training sequence:
        1. Signal server to trigger round (which signals waiting clients)
        2. Wait for updates
        3. Repeat
        """
        logger.info(f"Starting training sequence for {num_rounds} rounds")
        logger.info("="*70)
        
        for round_num in range(1, num_rounds + 1):
            logger.info(f"\n🔄 ROUND {round_num}/{num_rounds}")
            print("="*70)
            
            # Get status before round
            status = self.get_status()
            if not status:
                logger.error("Could not get status")
                continue
            
            current_round = status['round']
            logger.info(f"Triggering round {current_round} - signaling clients to train")
            
            # Signal server to trigger training
            if not self.signal_training_round():
                logger.error("Failed to trigger round")
                continue
            
            # Wait for updates
            logger.info(f"⏳ Waiting {wait_time}s for client updates...")
            time.sleep(wait_time)
            
            # Check status
            status = self.get_status()
            if not status:
                logger.error("Could not get status")
                continue
            
            # Print round summary
            total_received = sum(c['updates_received'] for c in status['clients'].values())
            total_accepted = sum(c['updates_accepted'] for c in status['clients'].values())
            total_rejected = sum(c['updates_rejected'] for c in status['clients'].values())
            
            print("\n" + "-"*70)
            logger.info(f"📊 Round {current_round} Summary:")
            logger.info(f"  ✓ Updates received: {total_received}")
            logger.info(f"  ✓ Updates accepted: {total_accepted}")
            logger.info(f"  ✗ Updates rejected: {total_rejected}")
            
            if status['attacks_detected_this_round'] > 0:
                logger.warning(f"  🔴 ATTACKS DETECTED: {status['attacks_detected_this_round']}")
                
                # Print which clients were detected
                for client_id, state in status['clients'].items():
                    if state['attacks_detected']:
                        recent_attacks = [a for a in state['attacks_detected'] if a['round'] == current_round]
                        if recent_attacks:
                            for attack in recent_attacks:
                                conf = attack.get('confidence', 0)
                                logger.warning(f"    └─ {client_id} (confidence={conf:.2f})")
                                
                                # Show attack types
                                if 'attacks' in attack:
                                    attack_types = [a['type'] for a in attack['attacks']]
                                    logger.warning(f"       Types: {', '.join(attack_types)}")
            else:
                logger.info(f"  ✓ No attacks detected")
            
            print("-"*70)
            logger.info(f"✓ Round {current_round} completed\n")
            time.sleep(2)
        
        logger.info("="*70)
        logger.info(f"✓ Training sequence completed {num_rounds} rounds")
        logger.info("="*70)
        self.print_status()

def main():
    parser = argparse.ArgumentParser(
        description='FL Control & Orchestration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show current status
  python control.py --mode status
  
  # Monitor continuously
  python control.py --mode monitor --interval 10
  
  # Reset round state (for testing between attack scenarios)
  python control.py --mode reset
  
  # Run 5 training rounds
  python control.py --mode train --rounds 5 --wait 100
        """
    )
    parser.add_argument('--mode', default='monitor',
                       choices=['status', 'monitor', 'train', 'reset'],
                       help='Operation mode')
    parser.add_argument('--rounds', type=int, default=5,
                       help='Number of rounds for training mode')
    parser.add_argument('--interval', type=int, default=10,
                       help='Monitoring interval in seconds')
    parser.add_argument('--wait', type=int, default=60,
                       help='Wait time for client updates in seconds')
    
    args = parser.parse_args()
    
    controller = FLController()
    
    # Check server health
    print("\n" + "="*70)
    print("FL CONTROLLER - Starting")
    print("="*70)
    
    if not controller.check_server_health():
        logger.error("Server is not available. Please start the server first.")
        sys.exit(1)
    
    # Execute requested mode
    if args.mode == 'status':
        controller.print_status()
    
    elif args.mode == 'monitor':
        controller.interactive_monitor(interval=args.interval)
    
    elif args.mode == 'reset':
        controller.reset_round()
        controller.print_status()
    
    elif args.mode == 'train':
        controller.run_training_sequence(num_rounds=args.rounds, wait_time=args.wait)

if __name__ == '__main__':
    main()