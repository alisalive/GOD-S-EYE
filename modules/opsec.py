"""
OPSEC Module — operational security scoring for red team engagements.
"""

import time
from core.orchestrator import EngagementState

# ── Deductions ────────────────────────────────────────────────────────────────
DEDUCTIONS = {
    "port_scan":        ("Port scan performed",          -15),
    "web_crawl":        ("Web crawl / endpoint enum",    -10),
    "sqli_test":        ("SQL injection probe",          -20),
    "ad_enum":          ("Active Directory enumeration", -15),
    "waf_bypass":       ("WAF bypass attempts",          -25),
    "screenshot":       ("Browser-based screenshots",    -5),
    "subdomain_enum":   ("Subdomain enumeration",        -10),
}

# ── Bonuses ───────────────────────────────────────────────────────────────────
BONUSES = {
    "ua_rotation":      ("User-Agent rotation enabled",  +10),
    "delays":           ("Random delays between requests", +10),
    "stealth_mode":     ("Stealth mode active",          +20),
}


class OpsecTracker:
    def __init__(self, base_score: int = 100):
        self.score = base_score
        self.events: list = []
        self.start_time = time.time()

    def deduct(self, event_key: str) -> int:
        if event_key in DEDUCTIONS:
            label, delta = DEDUCTIONS[event_key]
            self.score = max(0, self.score + delta)
            self.events.append({
                "type": "deduction",
                "key": event_key,
                "label": label,
                "delta": delta,
                "score_after": self.score,
                "timestamp": time.time() - self.start_time,
            })
        return self.score

    def bonus(self, event_key: str) -> int:
        if event_key in BONUSES:
            label, delta = BONUSES[event_key]
            self.score = min(120, self.score + delta)  # allow score above 100 before clamping
            self.events.append({
                "type": "bonus",
                "key": event_key,
                "label": label,
                "delta": delta,
                "score_after": self.score,
                "timestamp": time.time() - self.start_time,
            })
        return self.score

    def get_rating(self) -> str:
        if self.score >= 80:
            return "NINJA"
        elif self.score >= 60:
            return "GHOST"
        elif self.score >= 40:
            return "NOISY"
        elif self.score >= 20:
            return "LOUD"
        else:
            return "BUSTED"

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "rating": self.get_rating(),
            "events": self.events,
        }


def calculate_opsec_score(state: EngagementState, stealth: bool = False,
                           ua_rotation: bool = False, delays: bool = False) -> int:
    """
    Calculate OPSEC score based on engagement state.
    Updates state.opsec_score and returns final score.
    """
    tracker = OpsecTracker(base_score=100)

    # Apply bonuses first
    if stealth:
        tracker.bonus("stealth_mode")
    if ua_rotation:
        tracker.bonus("ua_rotation")
    if delays:
        tracker.bonus("delays")

    # Apply deductions based on what was done
    if state.recon_data.get("open_ports"):
        tracker.deduct("port_scan")

    if state.recon_data.get("web"):
        tracker.deduct("web_crawl")

    if state.recon_data.get("subdomains", {}).get("found"):
        tracker.deduct("subdomain_enum")

    if state.recon_data.get("screenshots"):
        tracker.deduct("screenshot")

    if state.web_data:
        sqli_found = any(
            v.get("sqli_findings") for v in state.web_data.values()
            if isinstance(v, dict)
        )
        if sqli_found:
            tracker.deduct("sqli_test")

    if state.ad_data.get("ad_detected"):
        tracker.deduct("ad_enum")

    waf_bypass_data = getattr(state, "waf_bypass_data", None)
    if waf_bypass_data:
        tracker.deduct("waf_bypass")

    state.opsec_score = tracker.score

    # Store tracker data for reporting
    if not hasattr(state, "opsec_tracker_data"):
        state.opsec_tracker_data = {}
    state.opsec_tracker_data = tracker.to_dict()

    return tracker.score


def get_opsec_recommendations(score: int) -> list:
    recs = []
    if score < 80:
        recs.append("Enable --stealth mode to add random delays between requests")
    if score < 70:
        recs.append("Use User-Agent rotation to blend with normal traffic")
    if score < 50:
        recs.append("Avoid aggressive scanning — use targeted probes only")
    if score < 30:
        recs.append("HIGH NOISE LEVEL — consider stopping to avoid detection")
    return recs
