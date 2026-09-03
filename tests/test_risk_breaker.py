# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from risk_breaker import RiskCircuitBreaker


def test_streak_waits_then_stops():
    env = {
        "GROK_RISK_STREAK_WAIT": "2",
        "GROK_RISK_STREAK_STOP": "4",
        "GROK_RISK_WAIT_BASE": "30",
        "GROK_RISK_WAIT_MAX": "300",
    }
    br = RiskCircuitBreaker(env)
    action, wait, streak = br.note_risk(now=1000)
    assert (action, wait, streak) == ("ok", 0.0, 1)
    action, wait, streak = br.note_risk(now=1001)
    assert action == "wait" and streak == 2 and wait == 30
    action, wait, streak = br.note_risk(now=1002)
    assert action == "wait" and streak == 3 and wait == 60
    action, wait, streak = br.note_risk(now=1003)
    assert action == "stop" and streak == 4
    assert br.should_stop() is True


def test_success_resets_streak():
    env = {"GROK_RISK_STREAK_WAIT": "2", "GROK_RISK_STREAK_STOP": "5"}
    br = RiskCircuitBreaker(env)
    br.note_risk(now=1)
    br.note_success()
    action, wait, streak = br.note_risk(now=2)
    assert (action, wait, streak) == ("ok", 0.0, 1)
    assert br.should_stop() is False


if __name__ == "__main__":
    test_streak_waits_then_stops()
    test_success_resets_streak()
    print("OK risk breaker")
