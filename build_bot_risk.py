"""Grok2API-style Build thinking probe (降智 / 号级风控).

Same rules as grok2api inspectBuildBotRisk:
- POST cli-chat-proxy /v1/responses stream grok-4.5 with reasoning.effort=high
- 2 sticky identities {account}+1 / {account}+2
- first thinking delta → clean (source 0)
- content delta without thinking → missing
- missing on every attempt → flagged source 2
- HTTP/empty/quota → inconclusive, not a hard risk
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable, Iterable

from webui.proxy_store import expand_proxy_url, is_sticky_template, sticky_account_key

BOT_RISK_PROBE_ATTEMPTS = 2
BOT_RISK_PROBE_MODEL = "grok-4.5"
# Keep in sync with sso_to_auth_json.CPA_PROBE_URL / CPA_GROK_HEADERS (Build CLI channel).
BOT_RISK_PROBE_URL = "https://cli-chat-proxy.grok.com/v1/responses"
# Align with grok2api RecommendedBuildClientVersion / applyHeaders(trace=true, streaming).
BOT_RISK_CLIENT_VERSION = "1.0.4"
BOT_RISK_PROBE_HEADERS = {
    "User-Agent": f"grok-shell/{BOT_RISK_CLIENT_VERSION} (linux; x86_64)",
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-authenticateresponse": "authenticate-response",
    "x-grok-client-identifier": "grok-shell",
    "x-grok-client-version": BOT_RISK_CLIENT_VERSION,
    "x-grok-client-mode": "headless",
    "Accept": "text/event-stream",
    "Accept-Encoding": "identity",
}
BOT_RISK_HTTP_RETRIES = 3
BOT_RISK_RETRY_STATUSES = {403, 429, 502, 503}
BOT_RISK_TOKEN_READY_SECONDS = 4.0
BOT_RISK_PROBE_PROMPT = (
    "Think step by step before answering. What is 17 multiplied by 19? Give the integer result."
)
BOT_RISK_ATTEMPT_TIMEOUT = 75

VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_THINKING = "thinking"
VERDICT_MISSING = "missing"

LogFn = Callable[[str], None]
HttpPost = Callable[..., Any]


def _text(value: object) -> str:
    return str(value or "").strip()


def _raw_json_string(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    if not isinstance(raw, (bytes, bytearray)):
        return ""
    blob = bytes(raw).strip()
    if len(blob) < 2 or blob[:1] != b'"':
        return ""
    try:
        text = json.loads(blob.decode("utf-8"))
    except Exception:
        return ""
    return text if isinstance(text, str) else ""


def _truncate(value: str, max_len: int = 80) -> str:
    runes = list(str(value or ""))
    if len(runes) <= max_len:
        return "".join(runes)
    return "".join(runes[:max_len]) + "…"


def _first_str(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return ""


def extract_upstream_error_metadata(body: str) -> tuple[str, str]:
    text = str(body or "").strip()
    if not text:
        return "", ""
    try:
        payload = json.loads(text)
    except Exception:
        return "", text.replace("\n", " ").strip()
    if not isinstance(payload, dict):
        return "", text.replace("\n", " ").strip()
    nested = payload.get("error")
    if isinstance(nested, dict):
        code = _first_str(
            nested.get("code"),
            nested.get("error_code"),
            payload.get("code"),
            payload.get("error_code"),
        )
        message = _first_str(
            nested.get("message"),
            nested.get("error"),
            payload.get("message"),
        )
        return code, message
    if isinstance(nested, str) and nested.strip():
        return _first_str(payload.get("code"), payload.get("error_code")), nested.strip()
    return (
        _first_str(payload.get("code"), payload.get("error_code")),
        _first_str(payload.get("message"), payload.get("error")),
    )


def summarize_probe_failure(status: int, body: str, err: str = "") -> str:
    if str(err or "").strip():
        return _truncate(str(err).strip(), 240)
    text = str(body or "").strip()
    low = text.lower()
    if text and ("<html" in low or "just a moment" in low):
        title = ""
        start = low.find("<title")
        if start >= 0:
            gt = text.find(">", start)
            end = low.find("</title>", start)
            if gt >= 0 and end > gt:
                title = text[gt + 1 : end].strip()
        label = "HTML 响应（可能是 Cloudflare 挑战）"
        if title:
            label = f"{label}: {title}"
        return _truncate(f"HTTP {status} · {label}" if status else label, 240)
    code, message = extract_upstream_error_metadata(text)
    if message and code:
        return _truncate(f"HTTP {status} · {code}: {message}" if status else f"{code}: {message}", 240)
    if message:
        return _truncate(f"HTTP {status} · {message}" if status else message, 240)
    if code:
        return _truncate(
            f"HTTP {status} · {code}（响应无 message）" if status else f"{code}（响应无 message）",
            240,
        )
    if text:
        return _truncate(f"HTTP {status} · {text.replace(chr(10), ' ')}" if status else text.replace("\n", " "), 240)
    if status:
        return f"HTTP {status} · 空响应体"
    return "请求失败"


def format_failed_probe_reason(attempts: list[dict]) -> str:
    if not attempts:
        return "探测失败"
    pieces: list[str] = []
    for att in attempts:
        parts: list[str] = []
        ident = _text(att.get("identity"))
        if ident:
            parts.append(ident)
        status = int(att.get("status") or 0)
        detail = _text(att.get("detail"))
        if status and f"HTTP {status}" not in detail:
            parts.append(f"HTTP {status}")
        parts.append(detail or _text(att.get("verdict")) or "无有效思考样本")
        piece = " · ".join(parts)
        if piece not in pieces:
            pieces.append(piece)
    return _truncate(" | ".join(pieces), 360)


def _read_response_body(resp, limit: int = 4096) -> str:
    chunks: list[bytes] = []
    total = 0
    iterator = getattr(resp, "iter_content", None)
    if callable(iterator):
        try:
            stream = iterator(chunk_size=512)
        except TypeError:
            try:
                stream = iterator()
            except Exception:
                stream = []
        try:
            for piece in stream:
                if not piece:
                    continue
                raw = piece if isinstance(piece, (bytes, bytearray)) else str(piece).encode("utf-8", "replace")
                chunks.append(bytes(raw))
                total += len(raw)
                if total >= limit:
                    break
        except Exception:
            pass
        if chunks:
            return b"".join(chunks)[:limit].decode("utf-8", "replace")
    content = getattr(resp, "content", None)
    if isinstance(content, (bytes, bytearray)) and content:
        return bytes(content[:limit]).decode("utf-8", "replace")
    return str(getattr(resp, "text", "") or "")[:limit]


def observe_thinking_payload(payload: bytes | str, result: dict) -> None:
    if result.get("verdict") in (VERDICT_THINKING, VERDICT_MISSING):
        return
    try:
        if isinstance(payload, str):
            event = json.loads(payload)
        else:
            event = json.loads(bytes(payload).decode("utf-8", "replace"))
    except Exception:
        return
    if not isinstance(event, dict):
        return
    event_type = _text(event.get("type"))
    err = event.get("error")
    if event_type in ("error", "response.error", "response.failed") or err:
        if isinstance(err, dict):
            code = _first_str(err.get("code"), err.get("error_code"), event.get("code"))
            message = _first_str(err.get("message"), err.get("error"), event.get("message"))
        else:
            code, message = extract_upstream_error_metadata(json.dumps(event, ensure_ascii=False))
            if not message:
                message = _first_str(err, event.get("message"))
        if message and code:
            result["error_message"] = f"{code}: {message}"
        elif message:
            result["error_message"] = message
        elif code:
            result["error_message"] = f"{code}（响应无 message）"
        if result.get("error_message"):
            result["event"] = event_type or "error"
            return
    if event_type in (
        "response.reasoning_text.delta",
        "response.reasoning_summary_text.delta",
    ):
        text = _text(_raw_json_string(event.get("delta")))
        if text:
            result["verdict"] = VERDICT_THINKING
            result["event"] = event_type
            result["delta"] = _truncate(text)
            return
    if event_type == "response.output_text.delta":
        text = _text(_raw_json_string(event.get("delta")))
        if text:
            result["verdict"] = VERDICT_MISSING
            result["event"] = event_type
            result["delta"] = _truncate(text)
            return
    for choice in event.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
        for key, name in (
            ("reasoning_content", "reasoning_content"),
            ("thinking_content", "thinking_content"),
            ("reasoning", "reasoning"),
        ):
            text = _text(delta.get(key))
            if text:
                result["verdict"] = VERDICT_THINKING
                result["event"] = name
                result["delta"] = _truncate(text)
                return
        content = delta.get("content")
        if content:
            result["verdict"] = VERDICT_MISSING
            result["event"] = "content"
            result["delta"] = _truncate(str(content))
            return


def scan_thinking_sse(lines: Iterable[object]) -> dict:
    result = {"verdict": VERDICT_INCONCLUSIVE, "event": "", "delta": "", "error_message": ""}
    for raw in lines:
        if raw is None:
            continue
        if isinstance(raw, bytes):
            line = raw.decode("utf-8", "replace")
        else:
            line = str(raw)
        trimmed = line.strip()
        if not trimmed.startswith("data:"):
            continue
        payload = trimmed[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        observe_thinking_payload(payload, result)
        if result["verdict"] in (VERDICT_THINKING, VERDICT_MISSING):
            return result
    return result


def sticky_probe_identity(email: str, attempt: int) -> str:
    base = sticky_account_key(email) or "grok_build"
    n = max(1, int(attempt or 1))
    # First hop uses the same sticky session as signup (already CF-warmed).
    # Later hops add +n like grok2api to confirm account-level, not IP-level.
    if n <= 1:
        return base
    return f"{base}+{n}"


def expand_probe_proxy(template: str, email: str, attempt: int) -> str:
    raw = str(template or "").strip()
    if not raw:
        return ""
    if not is_sticky_template(raw):
        return raw
    ident = sticky_probe_identity(email, attempt)
    return expand_proxy_url(raw, email=ident, account=ident, account_id=ident)


def _iter_sse_lines(resp) -> Iterable[object]:
    iterator = getattr(resp, "iter_lines", None)
    if callable(iterator):
        return iterator()
    text = str(getattr(resp, "text", "") or "")
    return text.splitlines()


def probe_thinking_once(
    access_token: str,
    *,
    proxy: str = "",
    timeout: float = BOT_RISK_ATTEMPT_TIMEOUT,
    http_post: HttpPost | None = None,
) -> dict:
    token = str(access_token or "").strip()
    if not token:
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "status": 0,
            "event": "",
            "delta": "",
            "detail": "missing access_token",
        }
    headers = dict(BOT_RISK_PROBE_HEADERS)
    headers["Authorization"] = f"Bearer {token}"
    headers["Content-Type"] = "application/json"
    headers["x-grok-req-id"] = str(uuid.uuid4())
    kwargs = {
        "headers": headers,
        "json": {
            "model": BOT_RISK_PROBE_MODEL,
            "input": BOT_RISK_PROBE_PROMPT,
            "stream": True,
            "store": False,
            "include": ["reasoning.encrypted_content"],
            "reasoning": {"effort": "high"},
        },
        "timeout": timeout,
        "stream": True,
    }
    if proxy:
        kwargs["proxy"] = proxy
    if http_post is None:
        from curl_cffi import requests as _cffi_requests

        poster = _cffi_requests.post
    else:
        poster = http_post
    try:
        resp = poster(BOT_RISK_PROBE_URL, **kwargs)
    except Exception as exc:
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "status": 0,
            "event": "",
            "delta": "",
            "detail": summarize_probe_failure(0, "", str(exc)),
            "retryable": True,
        }
    status = int(getattr(resp, "status_code", 0) or 0)
    cf_ray = ""
    try:
        cf_ray = str((getattr(resp, "headers", None) or {}).get("cf-ray") or "")
    except Exception:
        cf_ray = ""
    if status < 200 or status >= 300:
        body = _read_response_body(resp)
        detail = summarize_probe_failure(status, body)
        if cf_ray and "cf-ray=" not in detail:
            detail = f"{detail} cf-ray={cf_ray}"
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "status": status,
            "event": "",
            "delta": "",
            "detail": detail,
            "retryable": status in BOT_RISK_RETRY_STATUSES,
        }
    scan = scan_thinking_sse(_iter_sse_lines(resp))
    if scan["verdict"] == VERDICT_INCONCLUSIVE:
        scan["detail"] = scan.get("error_message") or "空流，无思考/正文 delta"
    else:
        scan["detail"] = scan.get("event") or scan["verdict"]
    scan["status"] = status
    return scan


def inspect_build_bot_risk(
    access_token: str,
    *,
    email: str = "",
    proxy_template: str = "",
    attempts: int = BOT_RISK_PROBE_ATTEMPTS,
    http_post: HttpPost | None = None,
    log: LogFn | None = None,
) -> dict:
    """Return {ok, flagged, source, reason, attempts} matching grok2api outcomes."""
    token = str(access_token or "").strip()
    template = str(proxy_template or "").strip()
    result = {
        "ok": False,
        "flagged": False,
        "source": 0,
        "reason": "",
        "attempts": [],
    }
    if not token:
        result["reason"] = "missing access_token"
        return result
    misses = 0
    total = max(1, int(attempts or BOT_RISK_PROBE_ATTEMPTS))
    live = http_post is None
    for n in range(1, total + 1):
        proxy = expand_probe_proxy(template, email, n)
        ident = sticky_probe_identity(email, n) if is_sticky_template(template) else f"direct+{n}"
        scan = {}
        for retry in range(BOT_RISK_HTTP_RETRIES + 1):
            scan = probe_thinking_once(token, proxy=proxy, http_post=http_post)
            status = int(scan.get("status") or 0)
            retryable = bool(scan.get("retryable")) or status in BOT_RISK_RETRY_STATUSES
            if scan.get("verdict") != VERDICT_INCONCLUSIVE or not retryable or retry >= BOT_RISK_HTTP_RETRIES:
                break
            if log:
                log(
                    f"[风控] Build 对话探测 {ident} HTTP {status}，{retry + 1}/{BOT_RISK_HTTP_RETRIES} 次重试"
                )
            if live:
                time.sleep(1.5 * (retry + 1))
        attempt = {
            "identity": ident,
            "proxy_sticky": is_sticky_template(template),
            "verdict": scan.get("verdict") or VERDICT_INCONCLUSIVE,
            "status": int(scan.get("status") or 0),
            "event": scan.get("event") or "",
            "detail": scan.get("detail") or "",
        }
        result["attempts"].append(attempt)
        if log:
            log(
                f"[风控] Build 对话探测 {ident} verdict={attempt['verdict']} "
                f"http={attempt['status'] or '-'} {attempt['event'] or attempt['detail']}"
            )
        verdict = attempt["verdict"]
        if verdict == VERDICT_THINKING:
            result["ok"] = True
            result["flagged"] = False
            result["source"] = 0
            result["reason"] = (
                f"thinking ({attempt['event']})" if attempt["event"] else "thinking"
            )
            return result
        if verdict == VERDICT_MISSING:
            misses += 1
            continue
        # 403/空流：换下一个粘性身份再探，不要整次判失败。
        if log:
            log(f"[风控] {ident} 探测未完成，换出口继续: {attempt['detail']}")
        continue
    if misses < total:
        result["reason"] = format_failed_probe_reason(result["attempts"]) or "有效无思考样本不足"
        return result
    result["ok"] = True
    result["flagged"] = True
    result["source"] = 2
    result["reason"] = f"no thinking on {len(result['attempts'])} sticky exits"
    return result
