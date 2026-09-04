"""Re-upload and Build thinking-probe helpers for registered accounts."""
from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

DETECT_WORKERS_MAX = 8
UPLOAD_PREPARE_WORKERS_MAX = 6
GROK2API_IMPORT_CHUNK = 40

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
    "workers": 0,
}


def job_status() -> dict:
    with _JOB_LOCK:
        return dict(_JOB)


def _set_job(**fields: Any) -> None:
    with _JOB_LOCK:
        _JOB.update(fields)


def _account_workers(kind: str, total: int) -> int:
    env_key = "GROK_ACCOUNT_WORKERS"
    raw = str(os.environ.get(env_key, "") or "").strip()
    try:
        configured = int(raw) if raw else 4
    except ValueError:
        configured = 4
    cap = DETECT_WORKERS_MAX if kind == "detect" else UPLOAD_PREPARE_WORKERS_MAX
    return max(1, min(cap, configured, max(1, int(total or 1))))


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


def _write_local_auth(token: dict, sso: str, email: str, log: LogFn | None = None) -> bool:
    import grok_register_ttk as register

    sso_n = register._normalize_sso_token(sso)
    record = register._s2cpa.token_to_cpa_record(
        token,
        email=email,
        sso=sso_n,
        bfs_info={"ok": True, "has_bfs": False, "source": "batch_upload"},
        check_bfs=False,
    )
    wrote = False
    auth_dir = str(register.config.get("cpa_auth_dir", "") or "").strip()
    remote_url = str(register.config.get("cpa_remote_url", "") or "").strip()
    management_key = str(register.config.get("cpa_management_key", "") or "").strip()
    g2a_dir = str(register.config.get("grok2api_auth_dir", "") or "").strip()
    root = Path(register.APP_DIR)
    if auth_dir and not os.path.isabs(auth_dir):
        auth_dir = str(root / auth_dir)
    if g2a_dir and not os.path.isabs(g2a_dir):
        g2a_dir = str(root / g2a_dir)
    if auth_dir:
        try:
            path = register._s2cpa.write_cpa_auth(register._s2cpa.Path(auth_dir), record)
            if log:
                log(f"{email} 已写入 CPA {path}")
            wrote = True
        except Exception as exc:
            if log:
                log(f"{email} CPA 本地写入失败: {exc}")
    if remote_url and management_key:
        try:
            name = register._s2cpa.upload_cpa_auth_remote(
                remote_url,
                management_key,
                record,
                proxy=register._resolve_cpa_proxy(),
            )
            if log:
                log(f"{email} 已上传 CPA 远程 {name}")
            wrote = True
        except Exception as exc:
            if log:
                log(f"{email} CPA 远程失败: {exc}")
    if g2a_dir:
        try:
            gpath = register._s2cpa.write_grok2api_auth(
                register._s2cpa.Path(g2a_dir), token, email=email
            )
            if log:
                log(f"{email} 已写入 grok2api 目录 {gpath}")
            wrote = True
        except Exception as exc:
            if log:
                log(f"{email} grok2api 目录写入失败: {exc}")
    return wrote


def _prepare_upload(email: str) -> dict:
    rec = get_account(email, secrets=True)
    if not rec:
        raise RuntimeError("账号不存在")
    logs: list[str] = []
    token = fresh_build_token(email, rec.get("sso") or "", log=logs.append)
    wrote = _write_local_auth(token, rec.get("sso") or "", email, log=logs.append)
    import grok2api_client as g2a

    entry = g2a.token_to_grok2api_account(token, email=email)
    return {
        "email": email,
        "sso": rec.get("sso") or "",
        "token": token,
        "entry": entry,
        "wrote": wrote,
        "logs": logs,
        "token_exp": _token_exp(token),
    }


def _g2a_settings() -> dict:
    import grok_register_ttk as register

    cfg = register.config
    return {
        "base_url": str(cfg.get("grok2api_base_url", "") or "").strip(),
        "admin_user": str(cfg.get("grok2api_admin_user", "") or "").strip(),
        "admin_password": str(cfg.get("grok2api_admin_password", "") or ""),
        "need_build": bool(cfg.get("grok2api_auto_upload", False)),
        "need_web": bool(cfg.get("grok2api_upload_web", False)),
        "need_console": bool(cfg.get("grok2api_upload_console", False)),
        "retries": int(cfg.get("grok2api_upload_retries", 3) or 3),
        "retry_delay_s": float(cfg.get("grok2api_upload_retry_delay_s", 2.0) or 2.0),
        "uploaded_web": bool(cfg.get("grok2api_upload_web")),
        "uploaded_build": bool(cfg.get("grok2api_auto_upload")),
        "uploaded_console": bool(cfg.get("grok2api_upload_console")),
    }


def _import_chunk(items: list[dict], settings: dict, log: LogFn | None = None) -> None:
    if not items:
        return
    need_remote = bool(
        settings.get("base_url")
        and settings.get("admin_user")
        and settings.get("admin_password")
        and (settings.get("need_build") or settings.get("need_web") or settings.get("need_console"))
    )
    if not need_remote:
        return
    import grok2api_client as g2a

    kwargs = {
        "base_url": settings["base_url"],
        "username": settings["admin_user"],
        "password": settings["admin_password"],
        "log": log,
        "retries": settings["retries"],
        "retry_delay_s": settings["retry_delay_s"],
    }
    if settings.get("need_build"):
        g2a.upload_build_accounts(
            kwargs["base_url"],
            kwargs["username"],
            kwargs["password"],
            [it["entry"] for it in items],
            log=log,
            retries=kwargs["retries"],
            retry_delay_s=kwargs["retry_delay_s"],
            filename=f"build-batch-{len(items)}.json",
        )
    sso_items = [{"sso_token": it["sso"], "email": it["email"]} for it in items if it.get("sso")]
    if settings.get("need_web") and sso_items:
        g2a.upload_sso_accounts(
            kwargs["base_url"],
            kwargs["username"],
            kwargs["password"],
            provider="grok_web",
            items=sso_items,
            log=log,
            retries=kwargs["retries"],
            retry_delay_s=kwargs["retry_delay_s"],
        )
    if settings.get("need_console") and sso_items:
        g2a.upload_sso_accounts(
            kwargs["base_url"],
            kwargs["username"],
            kwargs["password"],
            provider="grok_console",
            items=sso_items,
            log=log,
            retries=kwargs["retries"],
            retry_delay_s=kwargs["retry_delay_s"],
        )


def _mark_uploaded(item: dict, settings: dict, ok: bool, detail: str = "") -> dict:
    public = upsert_account(
        item["email"],
        sso=item.get("sso") or "",
        uploaded=bool(ok),
        uploaded_web=bool(ok and settings.get("uploaded_web")),
        uploaded_build=bool(ok and settings.get("uploaded_build")),
        uploaded_console=bool(ok and settings.get("uploaded_console")),
        upload_skipped=False,
        token_exp=int(item.get("token_exp") or 0),
    )
    return {
        "email": item["email"],
        "ok": bool(ok),
        "detail": detail or ("已批量入库" if ok else "上传失败"),
        "risk_status": public.get("risk_status") or "",
        "flagged": False,
    }


def _append_item(items: list[dict], row: dict, ok_n: int, fail_n: int) -> tuple[int, int]:
    items.append(row)
    if row.get("ok"):
        ok_n += 1
    else:
        fail_n += 1
    _set_job(done=len(items), ok=ok_n, failed=fail_n, items=list(items[-50:]))
    return ok_n, fail_n


def _run_upload_batch(emails: list[str]) -> None:
    settings = _g2a_settings()
    workers = _account_workers("upload", len(emails))
    _set_job(workers=workers)
    items: list[dict] = []
    ok_n = 0
    fail_n = 0
    prepared: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_prepare_upload, email): email for email in emails}
        for fut in as_completed(futs):
            email = futs[fut]
            try:
                prepared.append(fut.result())
            except Exception as exc:
                ok_n, fail_n = _append_item(
                    items,
                    {
                        "email": email,
                        "ok": False,
                        "detail": str(exc)[:240],
                        "risk_status": "",
                        "flagged": False,
                    },
                    ok_n,
                    fail_n,
                )
    chunk = GROK2API_IMPORT_CHUNK
    for start in range(0, len(prepared), chunk):
        group = prepared[start : start + chunk]
        logs: list[str] = []
        try:
            _import_chunk(group, settings, log=logs.append)
            detail = logs[-1] if logs else f"批量入库 {len(group)} 个"
            for item in group:
                if not item.get("wrote") and not (
                    settings.get("need_build") or settings.get("need_web") or settings.get("need_console")
                ):
                    ok_n, fail_n = _append_item(
                        items,
                        _mark_uploaded(item, settings, False, "CPA/grok2api 均未写入"),
                        ok_n,
                        fail_n,
                    )
                    continue
                ok_n, fail_n = _append_item(
                    items, _mark_uploaded(item, settings, True, detail), ok_n, fail_n
                )
        except Exception as exc:
            for item in group:
                try:
                    rec = upload_account(item["email"])
                    ok_n, fail_n = _append_item(
                        items,
                        {
                            "email": item["email"],
                            "ok": True,
                            "detail": rec.get("risk_detail") or "单条补传成功",
                            "risk_status": rec.get("risk_status") or "",
                            "flagged": False,
                        },
                        ok_n,
                        fail_n,
                    )
                except Exception as one_exc:
                    ok_n, fail_n = _append_item(
                        items,
                        _mark_uploaded(
                            item,
                            settings,
                            False,
                            f"批量失败后单条仍失败: {one_exc}"[:240],
                        ),
                        ok_n,
                        fail_n,
                    )
    _set_job(running=False, error="")


def _record_detect_result(email: str, rec: dict | None, exc: Exception | None) -> dict:
    if exc is not None:
        return {
            "email": email,
            "ok": False,
            "detail": str(exc)[:240],
            "risk_status": "",
            "flagged": False,
        }
    detect = rec.get("detect") if isinstance(rec, dict) else {}
    unknown = str((rec or {}).get("risk_status") or "") == "unknown"
    return {
        "email": email,
        "ok": not unknown,
        "detail": (detect or {}).get("reason")
        or (rec or {}).get("risk_detail")
        or "ok",
        "risk_status": (rec or {}).get("risk_status") or "",
        "flagged": bool((detect or {}).get("flagged")),
        "http_status": int((detect or {}).get("http_status") or 0),
    }


def _run_detect_batch(emails: list[str]) -> None:
    workers = _account_workers("detect", len(emails))
    _set_job(workers=workers)
    items: list[dict] = []
    ok_n = 0
    fail_n = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(detect_account, email): email for email in emails}
        for fut in as_completed(futs):
            email = futs[fut]
            try:
                rec = fut.result() or {}
                row = _record_detect_result(email, rec, None)
            except Exception as exc:
                row = _record_detect_result(email, None, exc)
            ok_n, fail_n = _append_item(items, row, ok_n, fail_n)
    _set_job(running=False, error="")


def _run_batch(kind: str, emails: list[str], worker: Callable[[str, LogFn | None], dict] | None = None) -> None:
    try:
        if kind == "upload":
            _run_upload_batch(emails)
            return
        if worker is None:
            _run_detect_batch(emails)
            return
        items: list[dict] = []
        ok_n = 0
        fail_n = 0
        workers = _account_workers(kind, len(emails))
        _set_job(workers=workers)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(worker, email, None): email for email in emails}
            for fut in as_completed(futs):
                email = futs[fut]
                try:
                    rec = fut.result() or {}
                    row = _record_detect_result(email, rec, None)
                except Exception as exc:
                    row = _record_detect_result(email, None, exc)
                ok_n, fail_n = _append_item(items, row, ok_n, fail_n)
        _set_job(running=False, error="")
    except Exception as exc:
        _set_job(running=False, error=str(exc)[:240])


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
                "workers": _account_workers(kind, len(addrs)),
            }
        )
    threading.Thread(
        target=_run_batch, args=(kind, addrs), daemon=True, name=f"accounts-{kind}"
    ).start()
    return job_status()
