"""
GOD'S EYE — Core Engine
"""

__version__ = "1.0.0"

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Mode(str, Enum):
    PENTEST = "pentest"
    REDTEAM = "redteam"


class Phase(str, Enum):
    RECON = "recon"
    SUBDOMAIN = "subdomain"
    WEB = "web"
    AD = "ad"
    CVE = "cve"
    SCREENSHOT = "screenshot"
    AI = "ai"
    REPORT = "report"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    remediation: str = ""
    cvss: float = 0.0
    phase: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "remediation": self.remediation,
            "cvss": self.cvss,
            "phase": self.phase,
            "timestamp": self.timestamp,
        }


@dataclass
class EngagementState:
    target: str
    mode: Mode
    scope: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    recon_data: dict = field(default_factory=dict)
    web_data: dict = field(default_factory=dict)
    ad_data: dict = field(default_factory=dict)
    cve_data: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    opsec_score: int = 100
    opsec_tracker_data: dict = field(default_factory=dict)
    waf_bypass_data: dict = field(default_factory=dict)
    default_creds_data: dict = field(default_factory=dict)
    msf_data: dict = field(default_factory=dict)
    dirbrute_data: dict = field(default_factory=dict)
    jwt_data: dict = field(default_factory=dict)
    shodan_data: dict = field(default_factory=dict)
    current_phase: Phase = Phase.RECON
    start_time: float = field(default_factory=time.time)
    notes: list = field(default_factory=list)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_note(self, note: str):
        self.notes.append(f"[{datetime.now().strftime('%H:%M:%S')}] {note}")

    def elapsed(self) -> str:
        secs = int(time.time() - self.start_time)
        return f"{secs // 60}m {secs % 60}s"

    def finding_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
