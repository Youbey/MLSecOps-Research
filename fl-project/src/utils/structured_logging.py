"""
Structured logging for Loki integration
Emits JSON logs that Grafana/Loki can parse and query
"""

import json
import logging
from datetime import datetime

class StructuredLogger:
    """
    Logger that emits structured JSON logs for Loki
    These logs can be queried in Grafana dashboards
    """
    
    def __init__(self, name="FL-STRUCTURED"):
        self.logger = logging.getLogger(name)
    
    def _emit(self, event_type, data):
        """Emit a structured log entry"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            **data
        }
        # Log as JSON string so Loki can parse it
        self.logger.info(json.dumps(log_entry))
    
    # ========================================================================
    # TRAINING EVENTS
    # ========================================================================
    
    def round_started(self, round_num, num_clients):
        """Log that a training round has started"""
        self._emit('ROUND_START', {
            'round': round_num,
            'num_clients': num_clients,
            'message': f'Round {round_num} started with {num_clients} clients'
        })
    
    def round_completed(self, round_num, updates_accepted, updates_rejected):
        """Log that a training round has completed"""
        self._emit('ROUND_END', {
            'round': round_num,
            'updates_accepted': updates_accepted,
            'updates_rejected': updates_rejected,
            'message': f'Round {round_num} completed: {updates_accepted} accepted, {updates_rejected} rejected'
        })
    
    def aggregation_completed(self, round_num, num_updates):
        """Log that model aggregation is complete"""
        self._emit('AGGREGATION_COMPLETED', {
            'round': round_num,
            'num_updates': num_updates,
            'message': f'Aggregated {num_updates} updates for round {round_num}'
        })
    
    # ========================================================================
    # SECURITY EVENTS
    # ========================================================================
    
    def attack_detected(self, round_num, client_id, attack_type, confidence, details=None):
        """Log an attack detection"""
        self._emit('ATTACK_DETECTED', {
            'round': round_num,
            'client_id': client_id,
            'attack_type': attack_type,
            'confidence': confidence,
            'severity': 'HIGH' if confidence > 0.9 else 'MEDIUM' if confidence > 0.7 else 'LOW',
            'details': details or {},
            'message': f'Attack detected: {client_id} - {attack_type} (confidence={confidence:.2f})'
        })
    
    def attack_rejected(self, round_num, client_id, attack_types):
        """Log that an update was rejected due to detected attacks"""
        self._emit('ATTACK_REJECTED', {
            'round': round_num,
            'client_id': client_id,
            'attack_types': attack_types,
            'message': f'Update rejected from {client_id} due to: {", ".join(attack_types)}'
        })
    
    def security_alert(self, alert_type, client_id, message, severity='MEDIUM'):
        """Log a general security alert"""
        self._emit('SECURITY_ALERT', {
            'alert_type': alert_type,
            'client_id': client_id,
            'severity': severity,
            'message': message
        })
    
    # ========================================================================
    # CLIENT EVENTS
    # ========================================================================
    
    def client_registered(self, client_id, num_samples):
        """Log client registration"""
        self._emit('CLIENT_REGISTERED', {
            'client_id': client_id,
            'num_samples': num_samples,
            'message': f'Client {client_id} registered with {num_samples} samples'
        })
    
    def client_update_received(self, round_num, client_id, loss, accuracy):
        """Log that an update was received from a client"""
        self._emit('CLIENT_UPDATE_RECEIVED', {
            'round': round_num,
            'client_id': client_id,
            'loss': loss,
            'accuracy': accuracy,
            'message': f'Update received from {client_id}: loss={loss:.4f}, acc={accuracy:.4f}'
        })
    
    def client_update_accepted(self, round_num, client_id):
        """Log that a client's update was accepted"""
        self._emit('CLIENT_UPDATE_ACCEPTED', {
            'round': round_num,
            'client_id': client_id,
            'message': f'Update accepted from {client_id}'
        })
    
    def client_update_rejected(self, round_num, client_id, reason):
        """Log that a client's update was rejected"""
        self._emit('CLIENT_UPDATE_REJECTED', {
            'round': round_num,
            'client_id': client_id,
            'reason': reason,
            'message': f'Update rejected from {client_id}: {reason}'
        })
    
    # ========================================================================
    # MODEL EVENTS
    # ========================================================================
    
    def model_performance(self, round_num, global_metrics):
        """Log global model performance metrics"""
        self._emit('MODEL_PERFORMANCE', {
            'round': round_num,
            'metrics': global_metrics,
            'message': f'Global model performance at round {round_num}'
        })
    
    # ========================================================================
    # SYSTEM EVENTS
    # ========================================================================
    
    def system_event(self, event_type, message, data=None):
        """Log a general system event"""
        self._emit(event_type, {
            'message': message,
            **(data or {})
        })

# Global structured logger instance
structured_logger = StructuredLogger()