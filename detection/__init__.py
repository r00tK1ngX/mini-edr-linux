"""Detection Engine package for Mini EDR Linux.

Exports rules, correlation engine, and main detection orchestrator.
"""

from detection.correlation import CorrelatedFinding, CorrelationEngine
from detection.engine import DetectionEngine
from detection.rules import (
    BaseRule,
    DetectionResult,
    FimDroppedBinaryRule,
    FimSensitiveFileRule,
    ProcessHiddenBinaryRule,
    ProcessHighCpuRule,
    ProcessHighMemoryRule,
    ProcessShellSpawnRule,
    ProcessSuspiciousPathRule,
    RuleRegistry,
)

__all__ = [
    "BaseRule",
    "CorrelatedFinding",
    "CorrelationEngine",
    "DetectionEngine",
    "DetectionResult",
    "FimDroppedBinaryRule",
    "FimSensitiveFileRule",
    "ProcessHiddenBinaryRule",
    "ProcessHighCpuRule",
    "ProcessHighMemoryRule",
    "ProcessShellSpawnRule",
    "ProcessSuspiciousPathRule",
    "RuleRegistry",
]
