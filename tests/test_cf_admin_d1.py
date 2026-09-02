# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import cf_admin, cloudflare, icloud


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = {} if data is None else data
        self.text = text or ""

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_mail_has_body_and_backoff():
    assert cf_admin.mail_has_body({"raw": "hello"})
    assert not cf_admin.mail_has_body({"id": "1", "address": "a@b.com"})
    assert cf_admin.next_poll_sleep(8, 0) == 8
    assert cf_admin.next_poll_sleep(8, 5) == cf_admin.MAX_POLL_INTERVAL


def test_jwt_empty_inbox_does_not_hit_admin():
    calls = []

    def http_get(url, headers=None, params=None):
        calls.append((url, dict(params or {})))
        if "/admin/" in url:
            return FakeResponse(200, {"results": [{"id": "all"}]})
        return FakeResponse(200, {"results": []})

    mails = cf_admin.list_messages(
        http_get,
        "https://mail.test",
        jwt="addr-jwt",
        admin_password="secret",
        target_email="user@mail.test",
    )
    assert mails == []
    assert len(calls) == 1
    assert "/api/mails" in calls[0][0]
    assert "/admin/mails" not in calls[0][0]
    assert int(calls[0][1]["limit"]) == cf_admin.MAIL_LIST_LIMIT


def test_jwt_401_uses_filtered_admin_not_unfiltered():
    calls = []

    def http_get(url, headers=None, params=None):
        calls.append((url, dict(params or {})))
        if "/api/mails" in url:
            return FakeResponse(401, {"error": "no"})
        return FakeResponse(200, {"results": []})

    mails = cf_admin.list_messages(
        http_get,
        "https://mail.test",
        jwt="bad",
        admin_password="secret",
        target_email="user@mail.test",
    )
    assert mails == []
    admin = [item for item in calls if "/admin/mails" in item[0]]
    assert admin
    assert all(item[1].get("address") == "user@mail.test" for item in admin)
    assert all("/user_api/mails" not in item[0] for item in calls)


def test_list_user_mails_does_not_probe_user_api():
    calls = []

    def http_get(url, headers=None, params=None):
        calls.append(url)
        return FakeResponse(200, {"results": []})

    cf_admin.list_user_mails(http_get, "https://mail.test", "jwt")
    assert calls == ["https://mail.test/api/mails"]


def test_health_check_skips_full_count():
    calls = []

    def http_get(url, headers=None, params=None):
        calls.append(dict(params or {}))
        return FakeResponse(200, {"results": []})

    ok, _detail = cf_admin.check_health(
        http_get, "https://mail.test", admin_password="secret"
    )
    assert ok
    assert calls[0].get("offset") == 1


def test_wait_for_code_skips_detail_when_raw_present():
    previous = cf_admin.time.sleep
    cf_admin.time.sleep = lambda _seconds: None
    try:
        calls = []
        raw = (
            "Subject: AB3-CD4 xAI\n\n"
            "SpaceXAI confirmation code: AB3-CD4\n"
        )

        def http_get(url, headers=None, params=None):
            calls.append(url)
            if url.rstrip("/").endswith("/1"):
                raise AssertionError(f"unexpected detail fetch: {url}")
            return FakeResponse(
                200,
                {
                    "results": [
                        {
                            "id": "1",
                            "address": "user@mail.test",
                            "subject": "AB3-CD4 xAI",
                            "raw": raw,
                        }
                    ]
                },
            )

        code = cf_admin.wait_for_code(
            http_get,
            "https://mail.test",
            email="user@mail.test",
            jwt="addr-jwt",
            admin_password="secret",
            timeout=2,
            poll_interval=8,
        )
        assert code
        assert all("/admin/mails/" not in url for url in calls)
    finally:
        cf_admin.time.sleep = previous


def test_cloudflare_wait_skips_detail_when_raw_present():
    calls = []

    def http_get(url, headers=None, params=None):
        calls.append(url)
        if "/api/mail/" in url or url.rstrip("/").endswith("/1"):
            raise AssertionError(f"unexpected detail fetch: {url}")
        return FakeResponse(
            200,
            {
                "results": [
                    {
                        "id": "1",
                        "address": "user@mail.test",
                        "subject": "AB3-CD4 xAI",
                        "raw": "SpaceXAI confirmation code: AB3-CD4",
                    }
                ]
            },
        )

    def _raise(_cb):
        return None

    def _sleep(_seconds, _cb):
        return None

    code = cloudflare.wait_for_code(
        http_get,
        "https://mail.test",
        "jwt",
        "user@mail.test",
        messages_path="/api/mails",
        timeout=2,
        poll_interval=8,
        raise_if_cancelled=_raise,
        sleep_with_cancel=_sleep,
    )
    assert code == "AB3-CD4"
    assert calls
    assert all("/api/mail/" not in url for url in calls)


def test_icloud_empty_forward_does_not_query_alias():
    admin_calls = []

    def fake_forward(*_a, **_k):
        return []

    def fake_admin(*_a, **_k):
        admin_calls.append(_k)
        return []

    with patch.object(icloud.cf_admin_provider, "list_forward_mailbox_mails", fake_forward), patch.object(
        icloud.cf_admin_provider, "list_admin_mails", fake_admin
    ), patch.object(icloud, "_sleep", lambda *_a, **_k: (_ for _ in ()).throw(Exception("stop"))):
        try:
            icloud.wait_for_verification_code(
                "alias@icloud.com",
                temp_mail_base="https://mail.test",
                temp_mail_password="pw",
                temp_mail_target="fwd@mail.test",
                http_get=lambda *_a, **_k: None,
                timeout=10,
            )
        except Exception as exc:
            assert "stop" in str(exc) or "未收到验证码" in str(exc)
    assert admin_calls == []


if __name__ == "__main__":
    test_mail_has_body_and_backoff()
    test_jwt_empty_inbox_does_not_hit_admin()
    test_jwt_401_uses_filtered_admin_not_unfiltered()
    test_list_user_mails_does_not_probe_user_api()
    test_health_check_skips_full_count()
    test_wait_for_code_skips_detail_when_raw_present()
    test_cloudflare_wait_skips_detail_when_raw_present()
    test_icloud_empty_forward_does_not_query_alias()
    print("ok")
