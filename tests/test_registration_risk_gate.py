# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register


def _clear_tls():
    register._proxy_tls.build_token = None
    register._proxy_tls.bot_risk_checked = False


def test_registration_risk_policy_html_helper_still_defined():
    blocked, detail = register._registration_risk_should_block(
        {"bot_flag_source": 2}
    )
    assert blocked is True
    assert "botFlagSource=2" in detail


def test_thinking_flagged_blocks_even_when_cpa_auto_add_is_disabled():
    _clear_tls()
    previous_auto_add = register.config.get("cpa_auto_add")
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._run_build_thinking_probe,
        register._append_sso_risk_rejected,
        register.record_register_result,
    )
    inspected = []
    quarantined = []
    recorded = []
    register.config["cpa_auto_add"] = False
    register._resolve_cpa_proxy = lambda: ""
    register._s2cpa.sso_to_token = (
        lambda sso, **_kwargs: inspected.append(sso)
        or {"access_token": "build-access", "refresh_token": "r"}
    )
    register._run_build_thinking_probe = lambda *_a, **_k: {
        "ok": True,
        "flagged": True,
        "source": 2,
        "reason": "no thinking on 2 sticky exits",
    }
    register._append_sso_risk_rejected = (
        lambda email, sso, details, **_kwargs: quarantined.append((email, sso, details))
    )
    register.record_register_result = (
        lambda status, email, **kwargs: recorded.append((status, email, kwargs))
    )
    try:
        try:
            register.ensure_sso_oauth_eligible(
                "sso=quarantined-token",
                email="risk@example.test",
            )
        except register.RegistrationRiskDenied:
            pass
        else:
            raise AssertionError("thinking-flagged SSO was not blocked")
    finally:
        (
            register._resolve_cpa_proxy,
            register._s2cpa.sso_to_token,
            register._run_build_thinking_probe,
            register._append_sso_risk_rejected,
            register.record_register_result,
        ) = previous_functions
        if previous_auto_add is None:
            register.config.pop("cpa_auto_add", None)
        else:
            register.config["cpa_auto_add"] = previous_auto_add

    assert inspected == ["quarantined-token"]
    assert quarantined == [
        (
            "risk@example.test",
            "quarantined-token",
            "no thinking on 2 sticky exits",
        )
    ]
    assert recorded[0][0:2] == ("risk", "risk@example.test")
    assert recorded[0][2]["bot_flag"] == 2


def test_thinking_clean_continues():
    _clear_tls()
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._run_build_thinking_probe,
        register._append_sso_risk_rejected,
    )
    quarantined = []
    register._resolve_cpa_proxy = lambda: ""
    register._s2cpa.sso_to_token = lambda *_a, **_k: {"access_token": "tok"}
    register._run_build_thinking_probe = lambda *_a, **_k: {
        "ok": True,
        "flagged": False,
        "source": 0,
        "reason": "thinking (response.reasoning_text.delta)",
    }
    register._append_sso_risk_rejected = lambda *_a, **_k: quarantined.append(True)
    try:
        state = register.ensure_sso_oauth_eligible("clean-token")
    finally:
        (
            register._resolve_cpa_proxy,
            register._s2cpa.sso_to_token,
            register._run_build_thinking_probe,
            register._append_sso_risk_rejected,
        ) = previous_functions
    assert state["found"] is True
    assert state["bot_flag_source"] == 0
    assert quarantined == []


def test_inconclusive_probe_does_not_quarantine():
    _clear_tls()
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._run_build_thinking_probe,
        register._append_sso_risk_rejected,
    )
    quarantined = []
    register._resolve_cpa_proxy = lambda: ""
    register._s2cpa.sso_to_token = lambda *_a, **_k: {"access_token": "tok"}
    register._run_build_thinking_probe = lambda *_a, **_k: {
        "ok": False,
        "flagged": False,
        "source": 0,
        "reason": "HTTP 403",
    }
    register._append_sso_risk_rejected = lambda *_a, **_k: quarantined.append(True)
    try:
        state = register.ensure_sso_oauth_eligible("maybe-token")
    finally:
        (
            register._resolve_cpa_proxy,
            register._s2cpa.sso_to_token,
            register._run_build_thinking_probe,
            register._append_sso_risk_rejected,
        ) = previous_functions
    assert state["found"] is False
    assert quarantined == []


if __name__ == "__main__":
    test_registration_risk_policy_html_helper_still_defined()
    test_thinking_flagged_blocks_even_when_cpa_auto_add_is_disabled()
    test_thinking_clean_continues()
    test_inconclusive_probe_does_not_quarantine()
    print("OK registration risk gate")
