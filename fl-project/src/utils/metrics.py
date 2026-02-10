"""
Prometheus metrics exporter for FL Server
Exposes metrics that Grafana dashboards can query
"""

from prometheus_client import Counter, Gauge, Histogram, generate_latest, REGISTRY
from flask import Response
import logging

logger = logging.getLogger("METRICS")

# ============================================================================
# TRAINING METRICS
# ============================================================================

# Current training round
fl_training_round = Gauge(
    'fl_training_round',
    'Current federated learning training round'
)

# Update counters
fl_updates_received = Counter(
    'fl_updates_received',
    'Total number of updates received from clients',
    ['client_id']
)

fl_updates_accepted = Counter(
    'fl_updates_accepted',
    'Total number of updates accepted',
    ['client_id']
)

fl_updates_rejected = Counter(
    'fl_updates_rejected',
    'Total number of updates rejected',
    ['client_id']
)

# ============================================================================
# SECURITY METRICS
# ============================================================================

# Attack detection counters
fl_attacks_detected = Counter(
    'fl_attacks_detected',
    'Total number of attacks detected',
    ['client_id', 'attack_type']
)

fl_attacks_high_confidence = Counter(
    'fl_attacks_high_confidence',
    'Number of high-confidence attacks (>90%)',
    ['client_id', 'attack_type']
)

# Current threat level (0-100)
fl_threat_level = Gauge(
    'fl_threat_level',
    'Current overall threat level (0-100)'
)

# ============================================================================
# CLIENT METRICS
# ============================================================================

fl_clients_registered = Gauge(
    'fl_clients_registered',
    'Number of registered clients'
)

fl_client_last_update = Gauge(
    'fl_client_last_update',
    'Timestamp of last update from client',
    ['client_id']
)

# ============================================================================
# MODEL PERFORMANCE METRICS
# ============================================================================

fl_model_loss = Gauge(
    'fl_model_loss',
    'Training loss reported by client',
    ['client_id']
)

fl_model_accuracy = Gauge(
    'fl_model_accuracy',
    'Training accuracy reported by client',
    ['client_id']
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def record_update_received(client_id):
    """Record that an update was received from a client"""
    fl_updates_received.labels(client_id=client_id).inc()
    logger.debug(f"Metrics: Update received from {client_id}")

def record_update_accepted(client_id):
    """Record that an update was accepted"""
    fl_updates_accepted.labels(client_id=client_id).inc()
    logger.debug(f"Metrics: Update accepted from {client_id}")

def record_update_rejected(client_id):
    """Record that an update was rejected"""
    fl_updates_rejected.labels(client_id=client_id).inc()
    logger.debug(f"Metrics: Update rejected from {client_id}")

def record_attack_detected(client_id, attack_type, confidence):
    """Record an attack detection"""
    fl_attacks_detected.labels(client_id=client_id, attack_type=attack_type).inc()
    
    if confidence > 0.9:
        fl_attacks_high_confidence.labels(client_id=client_id, attack_type=attack_type).inc()
    
    logger.debug(f"Metrics: Attack detected - {client_id}/{attack_type} (conf={confidence:.2f})")

def update_round(round_number):
    """Update the current round number"""
    fl_training_round.set(round_number)
    logger.debug(f"Metrics: Round updated to {round_number}")

def update_client_count(count):
    """Update the number of registered clients"""
    fl_clients_registered.set(count)
    logger.debug(f"Metrics: Client count updated to {count}")

def update_client_metrics(client_id, loss, accuracy):
    """Update client training metrics"""
    if loss is not None:
        fl_model_loss.labels(client_id=client_id).set(loss)
    if accuracy is not None:
        fl_model_accuracy.labels(client_id=client_id).set(accuracy)
    logger.debug(f"Metrics: Client {client_id} - loss={loss}, acc={accuracy}")

def update_threat_level(level):
    """Update overall threat level (0-100)"""
    fl_threat_level.set(level)
    logger.debug(f"Metrics: Threat level updated to {level}")

def get_metrics():
    """Return Prometheus metrics in text format"""
    return generate_latest(REGISTRY)

def create_metrics_endpoint(app):
    """Create /metrics endpoint for Prometheus to scrape"""
    @app.route('/metrics')
    def metrics():
        return Response(get_metrics(), mimetype='text/plain')
    
    logger.info("✓ Prometheus metrics endpoint created at /metrics")