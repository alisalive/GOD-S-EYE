"""
Tests for output/report.py — empty state report generation.
"""

import sys
import os
import tempfile
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import EngagementState, Mode, Finding, Severity
from output.report import generate_html_report, save_report


# ── Unit tests ────────────────────────────────────────────────────────────────

def _empty_state() -> EngagementState:
    return EngagementState(target="127.0.0.1", mode=Mode.PENTEST, scope=["127.0.0.1"])


def test_generate_html_report_empty_state():
    """Should generate valid HTML for empty state."""
    state = _empty_state()
    html = generate_html_report(state)
    assert "<!DOCTYPE html>" in html
    assert "127.0.0.1" in html
    assert "For authorized security testing only" in html
    assert len(html) > 1000


def test_generate_html_report_with_findings():
    """Should include findings in the report."""
    state = _empty_state()
    state.add_finding(Finding(
        title="Test SQLi Finding",
        severity=Severity.CRITICAL,
        description="SQL injection found",
        evidence="Error: You have an error in your SQL syntax",
        mitre_tactic="Initial Access",
        mitre_technique="T1190",
        remediation="Use parameterized queries",
        cvss=9.8,
        phase="web",
    ))
    html = generate_html_report(state)
    assert "Test SQLi Finding" in html
    assert "critical" in html.lower()
    assert "CVSS 9.8" in html


def test_generate_html_report_dark_aesthetic():
    """Report should use the permanent dark cybersecurity colour palette."""
    state = _empty_state()
    html = generate_html_report(state)
    # Background colour defined in the CSS palette
    assert "#0a0e1a" in html
    # Core JS helpers present
    assert "toggleCard" in html
    assert "animateCounter" in html


def test_generate_html_report_ai_section():
    """AI section should appear when analysis is provided."""
    state = _empty_state()
    ai_analysis = {
        "analysis": "Test AI analysis content",
        "tokens_used": 500,
        "model": "claude-sonnet-4-6",
    }
    html = generate_html_report(state, ai_analysis)
    assert "Test AI analysis content" in html
    assert "AI Executive Summary" in html


def test_generate_html_report_redteam_mode():
    """Red team mode should be reflected in report."""
    state = EngagementState(target="10.0.0.1", mode=Mode.REDTEAM, scope=["10.0.0.1"])
    html = generate_html_report(state)
    assert "Red Team" in html


def test_generate_html_report_no_xss():
    """Report should escape special characters in findings."""
    state = _empty_state()
    state.add_finding(Finding(
        title='<script>alert("xss")</script>',
        severity=Severity.HIGH,
        description="XSS test <img src=x onerror=alert(1)>",
        evidence="<body onload=alert(1)>",
        phase="web",
    ))
    html = generate_html_report(state)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_save_report_creates_files():
    """save_report should create HTML and JSON files."""
    state = _empty_state()
    state.add_finding(Finding(
        title="Test Finding",
        severity=Severity.MEDIUM,
        description="Test",
        phase="web",
    ))
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_report(state, None, tmpdir)
        assert "html" in paths
        assert "json" in paths
        assert os.path.isfile(paths["html"])
        assert os.path.isfile(paths["json"])
        assert os.path.getsize(paths["html"]) > 0
        assert os.path.getsize(paths["json"]) > 0


def test_save_report_json_structure():
    """JSON export should contain expected fields."""
    import json
    state = _empty_state()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_report(state, None, tmpdir)
        with open(paths["json"], "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["target"] == "127.0.0.1"
        assert data["mode"] == "pentest"
        assert "findings" in data
        assert "finding_counts" in data
        assert "opsec_score" in data
