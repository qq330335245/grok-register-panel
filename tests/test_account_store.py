# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import account_store


class Isolated:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.prev = (account_store.ACCOUNTS_DIR, account_store.DB_PATH, account_store._INIT)
        account_store.ACCOUNTS_DIR = base
        account_store.DB_PATH = base / "registry.sqlite"
        account_store._INIT = False
        return base

    def __exit__(self, *a):
        account_store.ACCOUNTS_DIR, account_store.DB_PATH, account_store._INIT = self.prev
        self.temp.cleanup()


def test_upsert_list_filter_and_secrets():
    with Isolated():
        account_store.upsert_account(
            "A@B.com",
            password="p1",
            sso="sso1",
            risk_status="clean",
            uploaded=True,
            uploaded_build=True,
        )
        account_store.upsert_account(
            "c@d.com",
            password="p2",
            sso="sso2",
            risk_status="unknown",
            uploaded=False,
            upload_skipped=True,
        )
        listed = account_store.list_accounts(query="b.com")
        assert listed["total"] == 1
        assert listed["items"][0]["email"] == "a@b.com"
        assert "sso" not in listed["items"][0]
        unknown = account_store.list_accounts(risk_status="unknown", uploaded="0")
        assert unknown["total"] == 1
        detail = account_store.get_account("a@b.com", secrets=True)
        assert detail["password"] == "p1"
        assert detail["sso"] == "sso1"
        big = account_store.list_accounts(page_size=500)
        assert big["page_size"] == 500
        assert listed["counts"]["clean"] == 1
        assert listed["counts"]["not_uploaded"] == 1


def test_delete_accounts_removes_row_and_file():
    with Isolated() as base:
        (base / "gone@x.com.txt").write_text("gone@x.com----pw----sso\n", encoding="utf-8")
        account_store.upsert_account("gone@x.com", password="pw", sso="sso")
        out = account_store.delete_accounts(["gone@x.com"])
        assert out["deleted"] == 1
        assert account_store.get_account("gone@x.com") is None
        assert not (base / "gone@x.com.txt").exists()


def test_parse_account_line():
    email, password, sso = account_store.parse_account_line("u@x.com----pw----sso-token")
    assert email == "u@x.com"
    assert password == "pw"
    assert sso == "sso-token"


if __name__ == "__main__":
    test_upsert_list_filter_and_secrets()
    test_delete_accounts_removes_row_and_file()
    test_parse_account_line()
    print("OK account store")
