#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json
from webui import delivery_store


class IsolatedConfig:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.previous = (delivery_store.CONFIG_PATH, delivery_store.LOCK_PATH)
        delivery_store.CONFIG_PATH = base / "config.json"
        delivery_store.LOCK_PATH = base / "config.json.lock"
        return delivery_store.CONFIG_PATH

    def __exit__(self, exc_type, exc, tb):
        delivery_store.CONFIG_PATH, delivery_store.LOCK_PATH = self.previous
        self.temp.cleanup()


def test_read_defaults_without_config():
    with IsolatedConfig():
        state = delivery_store.read_delivery_config()
        assert state["ok"] is True
        assert state["values"]["grok2api_admin_user"] == "admin"
        assert state["values"]["grok2api_admin_password"] == ""
        assert state["secret_configured"]["grok2api_admin_password"] is False
        assert state["upload_ready"] is False


def test_save_keeps_secret_when_blank():
    with IsolatedConfig() as path:
        atomic_write_json(
            path,
            {
                "email_provider": "icloud",
                "grok2api_admin_password": "keep-me",
                "cpa_management_key": "cpa-key",
            },
        )
        result = delivery_store.save_delivery_config(
            {
                "grok2api_auto_upload": True,
                "grok2api_upload_web": True,
                "grok2api_base_url": "https://g2a.example.invalid",
                "grok2api_admin_user": "admin",
                "grok2api_admin_password": "",
            }
        )
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["email_provider"] == "icloud"
        assert saved["grok2api_admin_password"] == "keep-me"
        assert saved["grok2api_auto_upload"] is True
        assert saved["grok2api_base_url"] == "https://g2a.example.invalid"
        assert result["values"]["grok2api_admin_password"] == ""
        assert result["secret_configured"]["grok2api_admin_password"] is True
        assert result["upload_ready"] is True


def test_clear_secret_and_reject_unknown():
    with IsolatedConfig() as path:
        atomic_write_json(path, {"grok2api_admin_password": "x"})
        delivery_store.save_delivery_config({}, clear_secrets=["grok2api_admin_password"])
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["grok2api_admin_password"] == ""
        try:
            delivery_store.save_delivery_config({"not_a_field": "1"})
        except delivery_store.DeliveryConfigError:
            pass
        else:
            raise AssertionError("expected DeliveryConfigError")


if __name__ == "__main__":
    test_read_defaults_without_config()
    test_save_keeps_secret_when_blank()
    test_clear_secret_and_reject_unknown()
    print("ok")
