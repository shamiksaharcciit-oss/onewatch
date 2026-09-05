"""Instrument health: the canary for the canary.

Probe-family headroom is a maintained property, not a design-time decision (Core -> Canary
Response 008 §3). A family calibrated against today's models will silently stop
discriminating; the only way to know is to re-measure against the baseline on a schedule
and surface saturation as a state rather than discover it during an incident.
"""
from canary.health.headroom import Headroom, HealthVerdict, measure
from canary.health.receipt import (HEALTH_RECEIPT_SCHEMA, build_health_receipt,
                                   check_health_receipt_id, health_receipt_body)
from canary.health.rederive import rederive_health

__all__ = ["Headroom", "HealthVerdict", "measure", "HEALTH_RECEIPT_SCHEMA",
           "build_health_receipt", "check_health_receipt_id", "health_receipt_body",
           "rederive_health"]
