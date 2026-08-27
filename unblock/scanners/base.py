from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    BLOCKING = "blocking"


@dataclass
class Signal:
    scanner_name: str
    severity: Severity
    description: str
    rule_id: str
    location: str | None = None
    safe_to_autofix: bool = False
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "severity": self.severity.value,
            "description": self.description,
            "rule_id": self.rule_id,
            "location": self.location,
            "safe_to_autofix": self.safe_to_autofix,
            "confidence": self.confidence,
        }


class Scanner:
    """Base class every scanner implements."""

    name: str = "base"

    def scan(self, repo_path: str) -> list[Signal]:
        raise NotImplementedError
