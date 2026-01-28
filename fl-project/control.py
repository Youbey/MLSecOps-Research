"""
Control script to:
1. Trigger training rounds
2. Monitor data flow between clients and server
3. Inspect model updates
"""

import requests
import json
import time
import sys
from datetime import datetime
import argparse

SERVER_URL = "http://localhost:5000"

class FLController:
    def __init__(self, server_url=SERVER_URL):
        self.server_url = server_url
        self.round = 0
    
    def check_server_health(self):
        """Check if server is running"""
        try:
            response = requests.get(f'{self.server_url}/health', timeout=2)
            data = response.json()
            print(f" Server is healthy (round {data['round']})")
            return True
        except:
            print(" Server is not responding")
            return False
    
    def get_status(self):
        """Get detailed server status"""
        try:
            response = requests.get(f'{self.server_url}/status')
            data = response.json()
            
            print("\n" + "="*60)
            print(f"FEDERATION STATUS - Round {data['round']}")
            print("="*60)
            
            print(f"\nClients ({len(data['clients'])} total):")
            for client_id, state in data['clients'].items():
                print(f"  {client_id}:")
                print(f"    - Updates sent: {state['updates_sent']}")
                print(f"    - Data samples: {state['data_samples']}")
                print(f"    - Last update: {state.get('last_update', 'Never')}")
                if 'last_metrics' in state:
                    metrics = state['last_metrics']
                    print(f"    - Loss: {metrics.get('loss', 'N/A'):.4f}")
                    print(f"    - Accuracy: {metrics.get('accuracy', 'N/A'):.4f}")
            
            print(f"\nPending updates from: {data['pending_updates']}")
            
            if data['history']:
                print(f"\nRecent rounds:")
                for entry in data['history'][-3:]:
                    print(f"  Round {entry['round']}: {entry['num_clients']} clients")
                    for cid, metrics in entry['client_metrics'].items():
                        print(f"    {cid}: loss={metrics.get('loss', 'N/A'):.4f}")
            
            print("="*60 + "\n")
            return data
        except Exception as e:
            print(f"Error getting status: {e}")
            return None
    
    def trigger_round(self):
        """Trigger federated aggregation round"""
        try:
            response = requests.post(f'{self.server_url}/trigger_round')
            data = response.json()
            
            if 'error' in data:
                print(f" Round failed: {data['error']}")
                return False
            
            print(f"\n Aggregation round {data['round']} completed")
            print(f"  - Clients aggregated: {data['clients_aggregated']}")
            return True
        except Exception as e:
            print(f" Error triggering round: {e}")
            return False
    
    def get_metrics(self):
        """Get Prometheus metrics"""
        try:
            response = requests.get(f'{self.server_url}/metrics')
            print("\n" + "="*60)
            print("PROMETHEUS METRICS")
            print("="*60)
            print(response.text)
        except Exception as e:
            print(f"Error fetching metrics: {e}")
    
    def interactive_monitor(self, interval=10):
        """Continuous monitoring mode"""
        print("Starting interactive monitoring (Ctrl+C to exit)")
        try:
            while True:
                self.get_status()
                print(f"Next update in {interval}s...\n")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped")
    
    def automated_training(self, num_rounds=5, wait_for_updates=120):
        """Automated training: wait for updates, aggregate, repeat"""
        print(f"Starting automated training for {num_rounds} rounds")
        print(f"Waiting {wait_for_updates}s for client updates each round\n")
        
        for round_num in range(1, num_rounds + 1):
            print(f"\n{'='*60}")
            print(f"ROUND {round_num}/{num_rounds}")
            print('='*60)
            
            # Wait for client updates
            print(f"Waiting {wait_for_updates}s for client updates...")
            time.sleep(wait_for_updates)
            
            # Check status
            status = self.get_status()
            if not status or not status['pending_updates']:
                print("No updates received, skipping aggregation")
                continue
            
            # Trigger aggregation
            print(f"\nTriggering aggregation for {len(status['pending_updates'])} updates...")
            self.trigger_round()
            
            time.sleep(2)
        
        print(f"\n Training completed {num_rounds} rounds")
        self.get_status()

def main():
    parser = argparse.ArgumentParser(description='FL Control & Monitoring')
    parser.add_argument('--mode', default='monitor',
                       choices=['monitor', 'status', 'trigger', 'metrics', 'train'],
                       help='Operation mode')
    parser.add_argument('--rounds', type=int, default=5,
                       help='Number of rounds for automated training')
    parser.add_argument('--interval', type=int, default=10,
                       help='Monitoring interval in seconds')
    parser.add_argument('--wait', type=int, default=120,
                       help='Wait time for client updates in seconds')
    
    args = parser.parse_args()
    
    controller = FLController()
    
    if not controller.check_server_health():
        sys.exit(1)
    
    if args.mode == 'status':
        controller.get_status()
    
    elif args.mode == 'trigger':
        controller.trigger_round()
    
    elif args.mode == 'metrics':
        controller.get_metrics()
    
    elif args.mode == 'monitor':
        controller.interactive_monitor(interval=args.interval)
    
    elif args.mode == 'train':
        controller.automated_training(num_rounds=args.rounds, wait_for_updates=args.wait)

if __name__ == '__main__':
    main()
