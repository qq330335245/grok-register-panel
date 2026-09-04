#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok2api_client as g2a


def _jwt(payload: dict) -> str:
    def b64(obj) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64(payload)}.x"


def test_normalize_base_url():
    assert g2a.normalize_base_url("127.0.0.1:18000") == "http://127.0.0.1:18000"
    assert g2a.normalize_base_url("https://g2a.example/") == "https://g2a.example"


def test_token_to_grok2api_account():
    access = _jwt(
        {
            "sub": "user-1",
            "email": "from-jwt@example.com",
            "exp": 2000000000,
            "bot_flag_source": 0,
        }
    )
    entry = g2a.token_to_grok2api_account(
        {
            "access_token": access,
            "refresh_token": "rt-1",
            "token_type": "Bearer",
            "expires_in": 3600,
        },
        email="override@example.com",
    )
    assert entry["provider"] == "grok_build"
    assert entry["email"] == "override@example.com"
    assert entry["user_id"] == "user-1"
    assert entry["refresh_token"] == "rt-1"
    assert entry["access_token"] == access
    assert entry["build_bot_flagged"] is False
    assert entry["client_id"] == g2a.GROK_BUILD_CLIENT_ID


def test_sso_account_entry():
    entry = g2a.sso_account_entry("grok_web", "sso=abc.def", email="a@b.com")
    assert entry["provider"] == "grok_web"
    assert entry["sso_token"] == "abc.def"
    assert entry["email"] == "a@b.com"


def test_pending_files():
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        entry = {
            "provider": "grok_build",
            "email": "a@b.com",
            "access_token": "at",
            "refresh_token": "rt",
        }
        path = g2a.save_upload_pending(entry, base_dir=base, error="boom")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["accounts"][0]["email"] == "a@b.com"
        assert data["accounts"][0]["upload_error"] == "boom"
        g2a.save_upload_pending(
            {**entry, "refresh_token": "rt-2"},
            base_dir=base,
        )
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["accounts"]) == 1
        assert data["accounts"][0]["refresh_token"] == "rt-2"
        web = g2a.save_sso_upload_pending(
            "grok_web", "sso-token", email="a@b.com", base_dir=base, error="x"
        )
        web_data = json.loads(web.read_text(encoding="utf-8"))
        assert web_data["accounts"][0]["sso_token"] == "sso-token"


def test_upload_build_accounts_sends_all_entries():
    captured = {}

    def fake_token(*args, **kwargs):
        return "admin-token"

    def fake_import(base_url, access_token, accounts, **kwargs):
        captured["accounts"] = accounts
        captured["filename"] = kwargs.get("filename")
        return {"created": len(accounts), "updated": 0, "synced": 0, "syncFailed": 0, "skipped": 0}

    orig_token, orig_import = g2a.get_access_token, g2a.import_build_accounts
    g2a.get_access_token = fake_token
    g2a.import_build_accounts = fake_import
    try:
        result = g2a.upload_build_accounts(
            "http://127.0.0.1:18000",
            "u",
            "p",
            [
                {"access_token": "a1", "email": "a@x.com"},
                {"refresh_token": "r2", "email": "b@x.com"},
            ],
            retries=0,
        )
    finally:
        g2a.get_access_token = orig_token
        g2a.import_build_accounts = orig_import
    assert result["created"] == 2
    assert len(captured["accounts"]) == 2
    assert captured["filename"] == "build-accounts.json"


def test_retriable_errors():
    assert g2a.is_retriable_upload_error("HTTP 502 bad gateway")
    assert g2a.is_retriable_upload_error("timed out")
    assert not g2a.is_retriable_upload_error("HTTP 401 unauthorized")
    assert not g2a.is_retriable_upload_error("no accounts to import")


if __name__ == "__main__":
    test_normalize_base_url()
    test_token_to_grok2api_account()
    test_sso_account_entry()
    test_pending_files()
    test_upload_build_accounts_sends_all_entries()
    test_retriable_errors()
    print("ok")
