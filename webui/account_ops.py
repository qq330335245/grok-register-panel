"""Re-upload and Build thinking-probe helpers for registered accounts."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from webui.account_store import (
    RISK_CLEAN,
    RISK_FLAGGED,
    RISK_UNKNOWN,
    get_account,
    upsert_account,
)

LogFn = Callable[[str], None]

_JOB_LOCK = threading.Lock()
_JOB: dict[str, Any] = {
    "running": False,
    "kind": "",
    "total": 0,
    "done": 0,
    "ok": 0,
    "failed": 0,
    "error": "",
    "items": [],
}


def job_status() -> dict:
    with _JOB_LOCK:
        return dict(_JOB)


def _set_job(**fields: Any) -> None:
    with _JOB_LOCK:
        _JOB.update(fields)


def _token_exp(token: dict | None) -> int:
    if not isinstance(token, dict):
        return 0
    try:
        from sso_to_auth_json import decode_jwt_payload

        payload = decode_jwt_payload(str(token.get("access_token") or ""))
        return int(payload.get("exp") or 0)
    except Exception:
        return 0


def _load_cpa_token(email: str) -> dict | None:
    try:
        import grok_register_ttk as register
    except Exception:
        return None
    auth_dir = str(register.config.get("cpa_auth_dir") or "cpa_auth").strip() or "cpa_auth"
    root = Path(register.APP_DIR)
    path = Path(auth_dir)
    if not path.is_absolute():
        path = root / path
    candidates = [
        path / f"xai-{email}.json",
        path / f"xai-{email.replace('@', '_')}.json",
    ]
    for cand in candidates:
        if not cand.is_file():
            continue
        try:
            data = json.loads(cand.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and data.get("access_token"):
            return data
    return None


def fresh_build_token(email: str, sso: str, log: LogFn | None = None) -> dict:
    """Return a Build token, refreshing via SSO when exp is missing or < 2 min."""
    existing = _load_cpa_token(email)
    exp = _token_exp(existing)
    now = int(time.time())
    if existing and exp and exp - now > 120:
        if log:
            log(f"{email} 使用未过期 access_token")
        return existing
    if not str(sso or "").strip():
        raise RuntimeError("没有 SSO，无法刷新 token")
    import grok_register_ttk as register

    if log:
        log(f"{email} token 将过期或缺失，用 SSO 重新换发")
    token = register._s2cpa.sso_to_token(
        register._normalize_sso_token(sso),
        proxy=register._resolve_cpa_proxy(),
        log=lambda m: log(str(m)) if log else None,
        prefer="device",
        allow_fallback=True,
        browser_approve=None,
    )
    if not token or not str(token.get("access_token") or "").strip():
        raise RuntimeError("SSO 换 token 失败")
    return token


def detect_account(email: str, log: LogFn | None = None) -> dict:
    rec = get_account(email, secrets=True)
    if not rec:
        raise RuntimeError("账号不存在")
    token = fresh_build_token(email, rec.get("sso") or "", log=log)
    from build_bot_risk import inspect_build_bot_risk
    import grok_register_ttk as register

    info = inspect_build_bot_risk(
        str(token.get("access_token") or ""),
        email=email,
        proxy_template=register.get_thread_proxy_template()
        or str(register.config.get("proxy") or ""),
        log=log,
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if info.get("flagged"):
        status = RISK_FLAGGED
    elif info.get("ok"):
        status = RISK_CLEAN
    else:
        status = RISK_UNKNOWN
    public = upsert_account(
        email,
        sso=rec.get("sso") or "",
        risk_status=status,
        risk_detail=str(info.get("reason") or ""),
        risk_checked_at=now,
        token_exp=_token_exp(token),
    )
    attempts = info.get("attempts") or []
    last = attempts[-1] if attempts else {}
    reason = str(info.get("reason") or last.get("detail") or "")
    public["detect"] = {
        "ok": bool(info.get("ok")),
        "flagged": bool(info.get("flagged")),
        "reason": reason,
        "http_status": int(last.get("status") or 0),
        "attempts": [
            {
                "identity": att.get("identity") or "",
                "status": int(att.get("status") or 0),
                "detail": att.get("detail") or "",
                "verdict": att.get("verdict") or "",
            }
            for att in attempts
        ],
    }
    public["risk_detail"] = reason or public.get("risk_detail") or ""
    return public


def upload_account(email: str, log: LogFn | None = None) -> dict:
    rec = get_account(email, secrets=True)
    if not rec:
        raise RuntimeError("账号不存在")
    token = fresh_build_token(email, rec.get("sso") or "", log=log)
    import grok_register_ttk as register

    register._cache_build_token(token)
    register._proxy_tls.bot_risk_checked = True
    ok = register.add_sso_to_cpa(
        rec.get("sso") or "",
        email=email,
        log_callback=log,
    )
    cfg = register.config
    public = upsert_account(
        email,
        sso=rec.get("sso") or "",
        uploaded=bool(ok),
        uploaded_web=bool(cfg.get("grok2api_upload_web")),
        uploaded_build=bool(cfg.get("grok2api_auto_upload")),
        uploaded_console=bool(cfg.get("grok2api_upload_console")),
        upload_skipped=False,
        token_exp=_token_exp(token),
    )
    if not ok:
        raise RuntimeError("上传未完成（CPA/grok2api 写入失败）")
    return public


def _run_batch(kind: str, emails: list[str], worker: Callable[[str, LogFn | None], dict]) -> None:
    items: list[dict] = []
    ok_n = 0
    fail_n = 0
    for index, email in enumerate(emails, start=1):
        logs: list[str] = []
        try:
            rec = worker(email, logs.append) or {}
            detect = rec.get("detect") if isinstance(rec, dict) else {}
            unknown = kind == "detect" and str(rec.get("risk_status") or "") == "unknown"
            ok_n += 0 if unknown else 1
            fail_n += 1 if unknown else 0
            items.append(
                {
                    "email": email,
                    "ok": not unknown,
                    "detail": (detect or {}).get("reason")
                    or rec.get("risk_detail")
                    or (logs[-1] if logs else "ok"),
                    "risk_status": rec.get("risk_status") or "",
                    "flagged": bool((detect or {}).get("flagged")),
                    "http_status": int((detect or {}).get("http_status") or 0),
                }
            )
        except Exception as exc:
            fail_n += 1
            items.append(
                {
                    "email": email,
                    "ok": False,
                    "detail": str(exc)[:240],
                    "risk_status": "",
                    "flagged": False,
                }
            )
        _set_job(done=index, ok=ok_n, failed=fail_n, items=list(items[-50:]))
    _set_job(running=False, error="")


def start_batch(kind: str, emails: list[str]) -> dict:
    kind = str(kind or "").strip().lower()
    if kind not in ("upload", "detect"):
        raise ValueError("kind 必须是 upload 或 detect")
    addrs = []
    seen = set()
    for raw in emails:
        email = str(raw or "").strip().lower()
        if email and "@" in email and email not in seen:
            seen.add(email)
            addrs.append(email)
    if not addrs:
        raise ValueError("没有有效邮箱")
    with _JOB_LOCK:
        if _JOB.get("running"):
            raise RuntimeError("已有任务在运行")
        _JOB.update(
            {
                "running": True,
                "kind": kind,
                "total": len(addrs),
                "done": 0,
                "ok": 0,
                "failed": 0,
                "error": "",
                "items": [],
            }
        )
    worker = upload_account if kind == "upload" else detect_account
    threading.Thread(
        target=_run_batch, args=(kind, addrs, worker), daemon=True, name=f"accounts-{kind}"
    ).start()
    return job_status()
