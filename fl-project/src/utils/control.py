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
        try:
            response = requests.post(
                f'{self.server_url}/trigger_aggregation',
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Aggregation triggered - now at round {data['round']}")
                return True
            else:
                logger.error(f"Failed to trigger aggregation: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error triggering aggregation: {e}")
            return False
    
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

    def trigger_round(self):
        """Signal the server to start a new training round"""
        try:
            # Assuming the endpoint is /start_round based on your logs
            response = requests.post(f'{self.server_url}/trigger_round')
            if response.status_code == 200:
                logger.info("Training round triggered at server")
                return True
            else:
                logger.error(f"Failed to start round: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error triggering round: {e}")
            return False

    def trigger_aggregation(self):
        """Signal the server to aggregate updates"""
        try:
            # Assuming the endpoint is /aggregate
            response = requests.post(f'{self.server_url}/aggregate')
            if response.status_code == 200:
                logger.info("✓ Aggregation triggered")
                return True
            else:
                logger.error(f"Failed to aggregate: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error triggering aggregation: {e}")
            return False

    def run_training_sequence(self, num_rounds=5, wait_time=60):
        """Run a sequence of training rounds with smart polling"""
        logger.info(f"Starting training sequence for {num_rounds} rounds")

        for i in range(num_rounds):
            logger.info("="*70)
            logger.info(f"🔄 ROUND {i+1}/{num_rounds}")

            # 1. Trigger the round
            if not self.trigger_round():
                logger.error("Failed to trigger round - stopping sequence")
                break

            # 2. Smart Wait Loop (Optimization)
            # We poll the server status to see if all clients have replied
            logger.info(f"⏳ Waiting for updates (polling every 2s, max {wait_time}s)...")
            start_time = time.time()

            while (time.time() - start_time) < wait_time:
                status = self.get_status()
                if status:
                    # In server.py, 'pending_updates' is list(server.client_updates.keys())
                    # This represents valid updates sitting in the buffer waiting for aggregation.
                    updates_received = len(status.get('pending_updates', []))
                    total_clients = len(status.get('clients', {}))

                    # If we have updates from all registered clients, stop waiting!
                    if total_clients > 0 and updates_received >= total_clients:
                        logger.info(f"✓ All clients reported ({updates_received}/{total_clients}). Proceeding immediately.")
                        break

                # Poll interval
                time.sleep(2)

            # 3. Trigger Aggregation
            logger.info("📊 Triggering model aggregation...")
            self.trigger_aggregation()

            # 4. Print Summary
            self.print_status()

            # Short buffer before next round to ensure logs are clean
            time.sleep(2)

        logger.info("="*70)
        logger.info(f"Training sequence completed {num_rounds} rounds")
        logger.info("="*70)

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