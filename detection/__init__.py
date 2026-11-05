"""Detection Engine package for Mini EDR Linux.

Exports rules, correlation engine, and main detection orchestrator.
"""

from detection.correlation import CorrelatedFinding, CorrelationEngine
from detection.engine import DetectionEngine
from detection.rules import (
    BaseRule,
    DetectionResult,
    FimSensitiveFileRule,
    ProcessHiddenBinaryRule,
    ProcessHighCpuRule,
    ProcessHighMemoryRule,
    ProcessSuspiciousPathRule,
    RuleRegistry,
)

__all__ = [
    "BaseRule",
    "CorrelatedFinding",
    "CorrelationEngine",
    "DetectionEngine",
    "DetectionResult",
    "FimSensitiveFileRule",
    "ProcessHiddenBinaryRule",
    "ProcessHighCpuRule",
    "ProcessHighMemoryRule",
    "ProcessSuspiciousPathRule",
    "RuleRegistry",
]
