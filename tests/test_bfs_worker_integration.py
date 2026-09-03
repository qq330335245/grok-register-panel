# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register


def _clear_tls():
    register._proxy_tls.build_token = None
    register._proxy_tls.bot_risk_checked = False


def test_thinking_flagged_in_cpa_path_raises():
    _clear_tls()
    config_keys = (
        "cpa_auto_add",
        "cpa_auth_dir",
        "cpa_remote_url",
        "cpa_management_key",
        "grok2api_auth_dir",
        "cpa_token_mode",
    )
    previous_config = {key: register.config.get(key) for key in config_keys}
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._run_build_thinking_probe,
        register._append_sso_risk_rejected,
        register.record_register_result,
    )
    with tempfile.TemporaryDirectory() as temp:
        register.config.update(
            {
                "cpa_auto_add": True,
                "cpa_auth_dir": str(Path(temp) / "cpa_auth"),
                "cpa_remote_url": "",
                "cpa_management_key": "",
                "grok2api_auth_dir": "",
                "cpa_token_mode": "device_protocol",
            }
        )
        register._resolve_cpa_proxy = lambda: ""
        register._s2cpa.sso_to_token = lambda *_args, **_kwargs: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
        }
        register._run_build_thinking_probe = lambda *_a, **_k: {
            "ok": True,
            "flagged": True,
            "source": 2,
            "reason": "no thinking on 2 sticky exits",
        }
        register._append_sso_risk_rejected = lambda *_a, **_k: None
        register.record_register_result = lambda *_a, **_k: {}
        try:
            try:
                register.add_sso_to_cpa("sso=test-sso-token", email="risk@example.test")
            except register.RegistrationRiskDenied:
                blocked = True
            else:
                blocked = False
        finally:
            (
                register._resolve_cpa_proxy,
                register._s2cpa.sso_to_token,
                register._run_build_thinking_probe,
                register._append_sso_risk_rejected,
                register.record_register_result,
            ) = previous_functions
            for key, value in previous_config.items():
                if value is None:
                    register.config.pop(key, None)
                else:
                    register.config[key] = value
    assert blocked is True


def test_grok2api_web_uploads_before_cpa_write():
    _clear_tls()
    order = []
    config_keys = (
        "cpa_auto_add",
        "cpa_auth_dir",
        "cpa_remote_url",
        "cpa_management_key",
        "grok2api_auth_dir",
        "grok2api_auto_upload",
        "grok2api_upload_web",
        "grok2api_upload_console",
        "grok2api_base_url",
        "grok2api_admin_user",
        "grok2api_admin_password",
        "bfs_check",
        "cpa_token_mode",
    )
    previous_config = {key: register.config.get(key) for key in config_keys}
    previous = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._run_build_thinking_probe,
        register._s2cpa.token_to_cpa_record,
        register._s2cpa.write_cpa_auth,
        register._s2cpa.write_grok2api_auth,
        register._g2a_client.upload_sso_account,
        register._g2a_client.upload_build_account,
        register._g2a_client.token_to_grok2api_account,
    )
    with tempfile.TemporaryDirectory() as temp:
        register.config.update(
            {
                "cpa_auto_add": True,
                "cpa_auth_dir": str(Path(temp) / "cpa_auth"),
                "cpa_remote_url": "",
                "cpa_management_key": "",
                "grok2api_auth_dir": str(Path(temp) / "g2a_auth"),
                "grok2api_auto_upload": True,
                "grok2api_upload_web": True,
                "grok2api_upload_console": False,
                "grok2api_base_url": "https://g2a.example.test",
                "grok2api_admin_user": "admin",
                "grok2api_admin_password": "secret",
                "bfs_check": False,
                "cpa_token_mode": "device_protocol",
            }
        )
        register._resolve_cpa_proxy = lambda: ""
        register._s2cpa.sso_to_token = lambda *_a, **_k: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
        }
        register._run_build_thinking_probe = lambda *_a, **_k: {
            "ok": True,
            "flagged": False,
            "source": 0,
            "reason": "thinking",
        }
        register._s2cpa.token_to_cpa_record = lambda *_a, **_k: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
        }
        register._s2cpa.write_cpa_auth = (
            lambda *_a, **_k: order.append("cpa") or Path(temp) / "cpa.json"
        )
        register._s2cpa.write_grok2api_auth = (
            lambda *_a, **_k: order.append("g2afile") or Path(temp) / "g2a.json"
        )
        register._g2a_client.token_to_grok2api_account = lambda *_a, **_k: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
            "email": "a@b.com",
        }
        register._g2a_client.upload_sso_account = (
            lambda *_a, **_k: order.append("web") or {"created": 1, "updated": 0}
        )
        register._g2a_client.upload_build_account = (
            lambda *_a, **_k: order.append("build")
            or {"created": 1, "updated": 0, "synced": 1, "syncFailed": 0}
        )
        try:
            result = register.add_sso_to_cpa("sso=test-sso-token", email="a@b.com")
        finally:
            (
                register._resolve_cpa_proxy,
                register._s2cpa.sso_to_token,
                register._run_build_thinking_probe,
                register._s2cpa.token_to_cpa_record,
                register._s2cpa.write_cpa_auth,
                register._s2cpa.write_grok2api_auth,
                register._g2a_client.upload_sso_account,
                register._g2a_client.upload_build_account,
                register._g2a_client.token_to_grok2api_account,
            ) = previous
            for key, value in previous_config.items():
                if value is None:
                    register.config.pop(key, None)
                else:
                    register.config[key] = value
    assert result is True
    assert order == ["web", "build", "cpa", "g2afile"]


if __name__ == "__main__":
    test_thinking_flagged_in_cpa_path_raises()
    test_grok2api_web_uploads_before_cpa_write()
    print("OK bfs worker integration")
