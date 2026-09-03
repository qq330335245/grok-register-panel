# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from build_bot_risk import (
    VERDICT_MISSING,
    VERDICT_THINKING,
    expand_probe_proxy,
    inspect_build_bot_risk,
    scan_thinking_sse,
    sticky_probe_identity,
)


def _data(obj: dict) -> str:
    return "data: " + json.dumps(obj)


def test_sse_thinking_beats_later_content():
    scan = scan_thinking_sse(
        [
            _data({"type": "response.reasoning_text.delta", "delta": "17*19"}),
            _data({"type": "response.output_text.delta", "delta": "323"}),
        ]
    )
    assert scan["verdict"] == VERDICT_THINKING
    assert scan["event"] == "response.reasoning_text.delta"


def test_sse_content_first_is_missing_thinking():
    scan = scan_thinking_sse(
        [
            _data({"type": "response.output_text.delta", "delta": "323"}),
            _data({"type": "response.reasoning_text.delta", "delta": "late"}),
        ]
    )
    assert scan["verdict"] == VERDICT_MISSING


def test_sse_choice_reasoning_content():
    scan = scan_thinking_sse(
        [
            _data(
                {
                    "choices": [
                        {"delta": {"reasoning_content": "step by step", "content": ""}}
                    ]
                }
            )
        ]
    )
    assert scan["verdict"] == VERDICT_THINKING
    assert scan["event"] == "reasoning_content"


def test_sticky_identity_and_expand():
    template = "socks5h://g2a.{account}:token@resin.example:2260"
    first = sticky_probe_identity("a@b.com", 1)
    ident = sticky_probe_identity("a@b.com", 2)
    assert "+" not in first
    assert ident.endswith("+2")
    expanded = expand_probe_proxy(template, "a@b.com", 2)
    assert "{account}" not in expanded
    assert ident in expanded


class _FakeResp:
    def __init__(self, status_code, lines=None, text=None, headers=None):
        self.status_code = status_code
        self._lines = list(lines or [])
        self.text = text if text is not None else "\n".join(self._lines)
        self.headers = headers or {}

    def iter_lines(self):
        return iter(self._lines)


def test_inspect_thinking_is_clean():
    def http_post(url, **kwargs):
        return _FakeResp(
            200,
            [_data({"type": "response.reasoning_text.delta", "delta": "think"})],
        )

    info = inspect_build_bot_risk(
        "access-token",
        email="a@b.com",
        proxy_template="socks5h://g2a.{account}:t@host:1",
        http_post=http_post,
    )
    assert info["ok"] is True
    assert info["flagged"] is False
    assert info["source"] == 0
    assert len(info["attempts"]) == 1


def test_inspect_two_missing_is_flagged():
    calls = []

    def http_post(url, **kwargs):
        calls.append(kwargs.get("proxy"))
        return _FakeResp(
            200,
            [_data({"type": "response.output_text.delta", "delta": "323"})],
        )

    info = inspect_build_bot_risk(
        "access-token",
        email="a@b.com",
        proxy_template="socks5h://g2a.{account}:t@host:1",
        http_post=http_post,
    )
    assert info["ok"] is True
    assert info["flagged"] is True
    assert info["source"] == 2
    assert len(info["attempts"]) == 2
    assert calls[0] != calls[1]
    assert "+2" in str(calls[1])
    assert "+2" not in str(calls[0])


def test_inspect_http_error_is_not_flagged():
    def http_post(url, **kwargs):
        return _FakeResp(403, ["<html>challenge</html>"])

    info = inspect_build_bot_risk("access-token", email="a@b.com", http_post=http_post)
    assert info["ok"] is False
    assert info["flagged"] is False
    assert "Cloudflare" in info["reason"] or "HTML" in info["reason"] or "403" in info["reason"]


def test_inspect_http_json_error_includes_message():
    body = json.dumps(
        {
            "error": {
                "code": "invalid_request",
                "message": "model grok-4.5 is not available for this account",
            }
        }
    )

    def http_post(url, **kwargs):
        return _FakeResp(403, text=body)

    info = inspect_build_bot_risk("access-token", email="a@b.com", http_post=http_post)
    assert info["ok"] is False
    assert info["flagged"] is False
    assert "invalid_request" in info["reason"]
    assert "model grok-4.5 is not available for this account" in info["reason"]


def test_inspect_http_code_only_notes_missing_message():
    def http_post(url, **kwargs):
        return _FakeResp(403, text=json.dumps({"error": {"code": "access_denied"}}))

    info = inspect_build_bot_risk("access-token", email="a@b.com", http_post=http_post)
    assert "access_denied" in info["reason"]
    assert "无 message" in info["reason"]


def test_sse_error_message_is_not_empty_stream():
    from build_bot_risk import probe_thinking_once

    def http_post(url, **kwargs):
        return _FakeResp(
            200,
            [_data({"type": "error", "error": {"code": "quota_exceeded", "message": "rate limit hit"}})],
        )

    scan = probe_thinking_once("access-token", http_post=http_post)
    assert scan["verdict"] == "inconclusive"
    assert "rate limit hit" in scan["detail"]
    assert "quota_exceeded" in scan["detail"]


if __name__ == "__main__":
    test_sse_thinking_beats_later_content()
    test_sse_content_first_is_missing_thinking()
    test_sse_choice_reasoning_content()
    test_sticky_identity_and_expand()
    test_inspect_thinking_is_clean()
    test_inspect_two_missing_is_flagged()
    test_inspect_http_error_is_not_flagged()
    test_inspect_http_json_error_includes_message()
    test_inspect_http_code_only_notes_missing_message()
    test_sse_error_message_is_not_empty_stream()
    print("OK build bot risk")
