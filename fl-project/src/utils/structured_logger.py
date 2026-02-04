"""
Structured JSON logging for FL Security Pipeline
Outputs JSON that Loki can parse and Grafana can visualize

Usage:
    from structured_logger import logger
    
    logger.log_test_start(attack_mode="POISONING", num_rounds=5)
    logger.log_round_start(round_number=1)
    logger.log_attack_detected("POISONING", "malicious_client", 0.95)
    logger.log_attack_rejected("POISONING", "malicious_client", 0.95)
    logger.log_round_end(round_number=1, success=True, attacks_detected=1)
    logger.log_test_end(success=True, final_accuracy=0.96)
"""

import json
import sys
from datetime import datetime
from typing import Optional, Dict, Any


class StructuredLogger:
    """
    Outputs structured JSON logs that Loki + Grafana can parse
    
    Each log entry is valid JSON with these base fields:
    - timestamp: ISO8601 UTC timestamp
    - level: INFO, WARNING, ERROR, CRITICAL
    - component: Which part of the system (FL_SERVER, TRAINING, DETECTION)
    - event_type: What happened (TEST_START, ATTACK_DETECTED, etc.)
    - message: Human-readable summary
    
    Plus any additional fields passed as kwargs
    """
    
    def __init__(self, component: str = "FL_SERVER"):
        """
        Initialize logger
        
        Args:
            component: Component name for log identification
        """
        self.component = component
    
    def _log(self, event_type: str, level: str = "INFO", 
             message: str = "", **kwargs):
        """
        Internal method to output structured JSON log entry
        
        This method:
        1. Creates JSON object with standard fields
        2. Adds all kwargs as additional fields
        3. Prints JSON to stdout (captured by Loki Docker driver)
        4. Flushes to ensure immediate output
        
        Args:
            event_type: Type of event (TEST_START, ATTACK_DETECTED, etc.)
            level: Log level (INFO, WARNING, ERROR, CRITICAL)
            message: Human-readable message summary
            **kwargs: Any additional fields to include in log
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "component": self.component,
            "event_type": event_type,
            "message": message,
        }
        
        # Add all additional fields
        log_entry.update(kwargs)
        
        # Output as JSON (stdout → Docker logging driver → Loki)
        print(json.dumps(log_entry))
        sys.stdout.flush()
    
    # =====================================================================
    # TEST LIFECYCLE EVENTS
    # =====================================================================
    
    def log_test_start(self, attack_mode: str, num_rounds: int, 
                       fl_wait_seconds: int = 15, notes: str = None):
        """
        Log when a test run starts
        
        Args:
            attack_mode: Type of attack (POISONING, STEALTHY, SYBIL_SIMULATION, GRADIENT_INVERSION, NONE)
            num_rounds: Number of training rounds
            fl_wait_seconds: Wait time between rounds
            notes: Optional notes about the test
        """
        self._log(
            event_type="TEST_START",
            level="INFO",
            message=f"Starting FL security test with {attack_mode} attack for {num_rounds} rounds",
            attack_mode=attack_mode,
            num_rounds=num_rounds,
            fl_wait_seconds=fl_wait_seconds,
            notes=notes,
            success=True
        )
    
    def log_test_end(self, success: bool, attack_mode: str = None,
                     total_attacks_detected: int = 0,
                     total_attacks_rejected: int = 0,
                     final_accuracy: float = None,
                     duration_seconds: int = None):
        """
        Log when a test run completes
        
        Args:
            success: Whether test completed successfully
            attack_mode: Type of attack tested
            total_attacks_detected: Total attacks detected in test
            total_attacks_rejected: Total attacks rejected
            final_accuracy: Final model accuracy
            duration_seconds: Total test duration
        """
        level = "INFO" if success else "ERROR"
        status = "SUCCESS" if success else "FAILED"
        message = f"Test completed - Status: {status}"
        
        if attack_mode:
            message += f" - Attack: {attack_mode}"
        if total_attacks_detected > 0:
            message += f" - Detected {total_attacks_detected} attacks"
        
        self._log(
            event_type="TEST_END",
            level=level,
            message=message,
            success=success,
            attack_mode=attack_mode,
            total_attacks_detected=total_attacks_detected,
            total_attacks_rejected=total_attacks_rejected,
            final_accuracy=final_accuracy,
            duration_seconds=duration_seconds
        )
    
    # =====================================================================
    # TRAINING ROUND EVENTS
    # =====================================================================
    
    def log_round_start(self, round_number: int, num_clients: int = None):
        """
        Log when a training round starts
        
        Args:
            round_number: Current round number
            num_clients: Number of clients participating
        """
        self._log(
            event_type="ROUND_START",
            level="INFO",
            message=f"Round {round_number} started",
            round_number=round_number,
            num_clients=num_clients,
            success=True
        )
    
    def log_round_end(self, round_number: int, success: bool,
                      num_clients: int = None,
                      updates_received: int = 0,
                      updates_accepted: int = 0,
                      updates_rejected: int = 0,
                      attacks_detected: int = 0,
                      round_accuracy: float = None,
                      aggregation_time_ms: float = None):
        """
        Log when a training round completes
        
        Args:
            round_number: Round number
            success: Whether round completed successfully
            num_clients: Number of clients
            updates_received: Total updates received
            updates_accepted: Updates accepted in aggregation
            updates_rejected: Updates rejected
            attacks_detected: Number of attacks detected
            round_accuracy: Model accuracy after round
            aggregation_time_ms: Time to aggregate in milliseconds
        """
        level = "INFO" if success else "ERROR"
        message = f"Round {round_number} completed"
        
        if attacks_detected > 0:
            message += f" - {attacks_detected} attack(s) detected"
        
        self._log(
            event_type="ROUND_END",
            level=level,
            message=message,
            round_number=round_number,
            success=success,
            metrics={
                "num_clients": num_clients,
                "updates_received": updates_received,
                "updates_accepted": updates_accepted,
                "updates_rejected": updates_rejected,
                "attacks_detected": attacks_detected,
                "round_accuracy": round_accuracy,
                "aggregation_time_ms": aggregation_time_ms
            }
        )
    
    # =====================================================================
    # ATTACK DETECTION EVENTS
    # =====================================================================
    
    def log_attack_detected(self, attack_type: str, client_id: str,
                            confidence: float, round_number: int = None,
                            evidence: Dict[str, Any] = None):
        """
        Log when an attack is detected
        
        Args:
            attack_type: Type of attack (POISONING, SYBIL, BYZANTINE, etc.)
            client_id: ID of attacking client
            confidence: Detection confidence (0.0 - 1.0)
            round_number: Round in which attack was detected
            evidence: Dictionary of detection evidence/metrics
        """
        # Determine severity based on confidence
        if confidence > 0.9:
            severity = "CRITICAL"
        elif confidence > 0.7:
            severity = "WARNING"
        else:
            severity = "INFO"
        
        message = f"{attack_type} detected from {client_id} (confidence: {confidence:.1%})"
        
        self._log(
            event_type="ATTACK_DETECTED",
            level=severity,
            message=message,
            attack_type=attack_type,
            client_id=client_id,
            confidence=round(confidence, 4),  # Round to 4 decimals
            round_number=round_number,
            evidence=evidence or {},
            success=False
        )
    
    def log_attack_rejected(self, attack_type: str, client_id: str,
                            confidence: float, round_number: int = None,
                            reason: str = None):
        """
        Log when a detected attack update is rejected
        
        Args:
            attack_type: Type of attack being rejected
            client_id: Client ID
            confidence: Detection confidence
            round_number: Round number
            reason: Reason for rejection
        """
        message = f"Update REJECTED from {client_id}: {reason or attack_type}"
        
        self._log(
            event_type="ATTACK_REJECTED",
            level="WARNING",
            message=message,
            attack_type=attack_type,
            client_id=client_id,
            confidence=round(confidence, 4),
            round_number=round_number,
            reason=reason,
            success=True  # Defense action successful
        )
    
    def log_update_accepted(self, client_id: str, round_number: int = None,
                            update_size_bytes: int = None):
        """
        Log when a benign update is accepted
        
        Args:
            client_id: Client that sent update
            round_number: Round number
            update_size_bytes: Size of update in bytes
        """
        message = f"Update ACCEPTED from {client_id}"
        
        self._log(
            event_type="UPDATE_ACCEPTED",
            level="INFO",
            message=message,
            client_id=client_id,
            round_number=round_number,
            update_size_bytes=update_size_bytes,
            success=True
        )
    
    # =====================================================================
    # CLIENT STATUS EVENTS
    # =====================================================================
    
    def log_client_suspicious(self, client_id: str, round_number: int = None,
                              reason: str = None, confidence: float = None):
        """
        Log when a client is marked as suspicious (low confidence detection)
        
        Args:
            client_id: Client ID
            round_number: Round number
            reason: Why client is suspicious
            confidence: Suspicion confidence
        """
        message = f"Client {client_id} marked SUSPICIOUS: {reason or 'Anomalous behavior'}"
        
        self._log(
            event_type="CLIENT_SUSPICIOUS",
            level="WARNING",
            message=message,
            client_id=client_id,
            round_number=round_number,
            reason=reason,
            confidence=confidence,
            success=False
        )
    
    def log_client_isolated(self, client_id: str, reason: str = None):
        """
        Log when a client is isolated from the network
        
        Args:
            client_id: Client ID
            reason: Reason for isolation
        """
        message = f"Client {client_id} ISOLATED: {reason or 'Security threat'}"
        
        self._log(
            event_type="CLIENT_ISOLATED",
            level="CRITICAL",
            message=message,
            client_id=client_id,
            reason=reason,
            success=True  # Isolation successful
        )
    
    # =====================================================================
    # ERROR & EXCEPTION EVENTS
    # =====================================================================
    
    def log_error(self, message: str, error_type: str = None,
                  error_details: str = None, round_number: int = None, **kwargs):
        """
        Log an error or exception
        
        Args:
            message: Error message
            error_type: Type of error
            error_details: Detailed error information
            round_number: Round when error occurred
            **kwargs: Additional context
        """
        self._log(
            event_type="ERROR",
            level="ERROR",
            message=message,
            error_type=error_type,
            error_details=error_details,
            round_number=round_number,
            success=False,
            **kwargs
        )
    
    def log_critical(self, message: str, error_type: str = None, **kwargs):
        """
        Log a critical event that may require immediate attention
        
        Args:
            message: Critical event message
            error_type: Type of critical event
            **kwargs: Additional context
        """
        self._log(
            event_type="CRITICAL",
            level="CRITICAL",
            message=message,
            error_type=error_type,
            success=False,
            **kwargs
        )
    
    # =====================================================================
    # GENERIC LOGGING
    # =====================================================================
    
    def log(self, event_type: str, message: str, level: str = "INFO", **kwargs):
        """
        Generic logging for any event
        
        Args:
            event_type: Type of event
            message: Event message
            level: Log level (INFO, WARNING, ERROR, CRITICAL)
            **kwargs: Additional fields
        """
        self._log(
            event_type=event_type,
            level=level,
            message=message,
            **kwargs
        )
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self._log(event_type="INFO", level="INFO", message=message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._log(event_type="WARNING", level="WARNING", message=message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._log(event_type="DEBUG", level="INFO", message=message, **kwargs)


# Create singleton instance for convenience
logger = StructuredLogger("FL_SERVER")

# Export
__all__ = ['StructuredLogger', 'logger']