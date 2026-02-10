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
                print(f"    ATTACKS DETECTED: {len(state['attacks_detected'])}")
        
        print(f"\nPending updates: {status['pending_updates']}")
        print(f"Attacks detected this round: {status['attacks_detected_this_round']}")
        print(f"Total attacks detected: {status['total_attacks_detected']}")
        
        if status['attacks_detected_this_round'] > 0:
            sec_status = requests.get(f'{self.server_url}/security/status').json()
            print(f"\nDetected attacks:")
            for attack in sec_status['attacks']:
                if attack['round'] == status['round']:
                    print(f"  Round {attack['round']}: {attack['client_id']} (confidence={attack['confidence']:.2f})")
    
    def signal_training_round(self):
        """Tell server to signal all clients to begin training"""
        # Note: In this simplified version, the server signals clients
        # In a real implementation, you might use a dedicated endpoint
        logger.info(f"Signaling clients to begin training")
        try:
            # Make a request to the server to signal clients
            # This is handled by the /wait_for_round endpoint with threading
            return True
        except Exception as e:
            logger.error(f"Error signaling clients: {e}")
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
        # In this simplified version, aggregation is triggered manually
        # You would need to add a /trigger_round endpoint if needed
        logger.info("Aggregation complete (clients' updates have been processed)")
        return True
    
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
    
    def signal_training_round(self):
        """Signal server to trigger training round"""
        try:
            response = requests.post(
                f'{self.server_url}/trigger_round',
                timeout=5
            )
            if response.status_code == 200:
                logger.info("Training round triggered at server")
                return True
        except Exception as e:
            logger.error(f"Error triggering round: {e}")
        return False

    def run_training_sequence(self, num_rounds=5, wait_time=60):
        """
        Full training sequence:
        1. Signal server to trigger round (which signals waiting clients)
        2. Wait for updates
        3. Repeat
        """
        logger.info(f"Starting training sequence for {num_rounds} rounds")

        for round_num in range(1, num_rounds + 1):
            logger.info(f"ROUND {round_num}/{num_rounds}")
            print("="*70)

            # Get status before round
            status = self.get_status()
            if not status:
                logger.error("Could not get status")
                continue

            current_round = status['round']
            logger.info(f"Triggering round {current_round} - signaling clients to train")

            # Signal server to trigger training
            self.signal_training_round()

            # Wait for updates
            logger.info(f"Waiting {wait_time}s for client updates...")
            time.sleep(wait_time)

            # Check status
            status = self.get_status()
            if not status:
                logger.error("Could not get status")
                continue

            # Print round summary - UTILISATION DE .get() POUR ÉVITER LES CRASH
            total_received = sum(c.get('updates_received', 0) for c in status['clients'].values())
            total_accepted = sum(c.get('updates_accepted', 0) for c in status['clients'].values())
            total_rejected = sum(c.get('updates_rejected', 0) for c in status['clients'].values())

            logger.info(f"Round {current_round} Summary:")
            logger.info(f"  - Updates received: {total_received}")
            logger.info(f"  - Updates accepted: {total_accepted}")
            logger.info(f"  - Updates rejected: {total_rejected}")

            if status.get('attacks_detected_this_round', 0) > 0:
                logger.warning(f"  - ATTACKS DETECTED: {status['attacks_detected_this_round']}")

                # Print which clients were detected
                for client_id, state in status['clients'].items():
                    # Check keys safely
                    attacks = state.get('attacks_detected', [])
                    if attacks:
                        for attack in attacks:
                            if attack.get('round') == current_round:
                                logger.warning(f"    {client_id} (confidence={attack.get('confidence', 0):.2f})")

            logger.info(f"Round {current_round} completed")
            time.sleep(2)

        logger.info(f"Training sequence completed {num_rounds} rounds")
        self.print_status()

def main():
    parser = argparse.ArgumentParser(description='FL Control & Orchestration')
    parser.add_argument('--mode', default='monitor',
                       choices=['status', 'monitor', 'train'],
                       help='Operation mode')
    parser.add_argument('--rounds', type=int, default=5,
                       help='Number of rounds for training mode')
    parser.add_argument('--interval', type=int, default=10,
                       help='Monitoring interval in seconds')
    parser.add_argument('--wait', type=int, default=60,
                       help='Wait time for client updates in seconds')
    
    args = parser.parse_args()
    
    controller = FLController()
    
    if not controller.check_server_health():
        sys.exit(1)
    
    if args.mode == 'status':
        controller.print_status()
    
    elif args.mode == 'monitor':
        controller.interactive_monitor(interval=args.interval)
    
    elif args.mode == 'train':
        controller.run_training_sequence(num_rounds=args.rounds, wait_time=args.wait)

if __name__ == '__main__':
    main()