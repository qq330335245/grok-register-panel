# -*- coding: utf-8 -*-
"""grok2api admin API client: login plus Build, Web, and Console imports."""
from __future__ import annotations

import base64
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

GROK_BUILD_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"

LogFn = Callable[[str], None]


def _curl():
    from curl_cffi import CurlMime, requests as curl_requests

    return CurlMime, curl_requests

_token_lock = threading.Lock()
_token_cache: dict[str, Any] = {
    "access_token": "",
    "expires_at": 0.0,
    "base_url": "",
    "username": "",
}


def normalize_base_url(value: str) -> str:
    base = str(value or "").strip().rstrip("/")
    if not base:
        return ""
    if not base.lower().startswith(("http://", "https://")):
        base = "http://" + base
    return base.rstrip("/")


def _log(log: LogFn | None, message: str) -> None:
    if log:
        log(str(message).strip())


def _parse_expires_at(value: object) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0


def _extract_access_token(payload: dict) -> tuple[str, float]:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        data = payload if isinstance(payload, dict) else {}
    tokens = data.get("tokens") if isinstance(data, dict) else None
    if not isinstance(tokens, dict):
        tokens = data if isinstance(data, dict) else {}
    access = str(
        tokens.get("accessToken")
        or tokens.get("access_token")
        or data.get("accessToken")
        or ""
    ).strip()
    expires_at = _parse_expires_at(
        tokens.get("accessTokenExpiresAt") or tokens.get("access_token_expires_at") or ""
    )
    return access, expires_at


def login_admin(
    base_url: str,
    username: str,
    password: str,
    *,
    timeout: float = 30,
    log: LogFn | None = None,
) -> str:
    base = normalize_base_url(base_url)
    user = str(username or "").strip()
    pwd = str(password or "")
    if not base:
        raise ValueError("grok2api_base_url is empty")
    if not user or not pwd:
        raise ValueError("grok2api admin username/password is empty")

    url = f"{base}/api/admin/v1/auth/login"
    _log(log, f"admin login -> {url} user={user}")
    _CurlMime, requests = _curl()
    resp = requests.post(
        url,
        json={"username": user, "password": pwd},
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=timeout,
        impersonate="chrome131",
    )
    body_text = (resp.text or "").strip()
    try:
        payload = resp.json() if body_text else {}
    except Exception:
        payload = {}
    if resp.status_code >= 400:
        err = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(err, dict):
            msg = f"{err.get('code') or 'loginFailed'}: {err.get('message') or body_text[:200]}"
        else:
            msg = body_text[:300] or resp.reason
        raise RuntimeError(f"admin login failed HTTP {resp.status_code}: {msg}")

    access, expires_at = _extract_access_token(payload if isinstance(payload, dict) else {})
    if not access:
        raise RuntimeError(f"admin login response missing accessToken: {body_text[:300]}")
    if expires_at <= 0:
        expires_at = time.time() + 50 * 60
    with _token_lock:
        _token_cache["access_token"] = access
        _token_cache["expires_at"] = expires_at
        _token_cache["base_url"] = base
        _token_cache["username"] = user
    _log(log, "admin login OK")
    return access


def get_access_token(
    base_url: str,
    username: str,
    password: str,
    *,
    force: bool = False,
    timeout: float = 30,
    log: LogFn | None = None,
) -> str:
    base = normalize_base_url(base_url)
    user = str(username or "").strip()
    now = time.time()
    with _token_lock:
        cached = str(_token_cache.get("access_token") or "")
        same = (
            cached
            and _token_cache.get("base_url") == base
            and _token_cache.get("username") == user
            and float(_token_cache.get("expires_at") or 0) - 60 > now
        )
        if same and not force:
            return cached
    return login_admin(base, user, password, timeout=timeout, log=log)


def _parse_sse_events(text: str) -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    event_name = "message"
    data_lines: list[str] = []
    for raw in str(text or "").splitlines():
        line = raw.rstrip("\r")
        if not line:
            if data_lines:
                events.append((event_name or "message", "\n".join(data_lines)))
            event_name = "message"
            data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip() or "message"
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
            continue
    if data_lines:
        events.append((event_name or "message", "\n".join(data_lines)))
    return events


_PROVIDER_IMPORT_PATHS = {
    "grok_build": "/api/admin/v1/accounts/import",
    "grok_web": "/api/admin/v1/accounts/web/import",
    "grok_console": "/api/admin/v1/accounts/console/import",
}


def _import_provider_accounts(
    base_url: str,
    access_token: str,
    accounts: list[dict] | dict,
    *,
    provider: str,
    timeout: float = 180,
    log: LogFn | None = None,
    filename: str = "accounts.json",
) -> dict[str, int]:
    provider = str(provider or "").strip().lower()
    try:
        endpoint = _PROVIDER_IMPORT_PATHS[provider]
    except KeyError as exc:
        raise ValueError(f"unsupported grok2api provider: {provider}") from exc
    base = normalize_base_url(base_url)
    token = str(access_token or "").strip()
    if not base:
        raise ValueError("grok2api_base_url is empty")
    if not token:
        raise ValueError("access token is empty")

    if isinstance(accounts, dict) and "accounts" in accounts:
        document = accounts
        entries = accounts.get("accounts") or []
    elif isinstance(accounts, list):
        document = {"accounts": accounts}
        entries = accounts
    elif isinstance(accounts, dict):
        document = {"accounts": [accounts]}
        entries = [accounts]
    else:
        raise ValueError("accounts must be dict or list")

    if not entries:
        raise ValueError("no accounts to import")

    payload = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    url = f"{base}{endpoint}"
    _log(log, f"import {provider} accounts n={len(entries)} -> {url}")

    CurlMime, requests = _curl()
    multipart = CurlMime()
    try:
        multipart.addpart(
            name="files",
            filename=filename or "build-accounts.json",
            content_type="application/json",
            data=payload.encode("utf-8"),
        )
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/event-stream",
            },
            multipart=multipart,
            timeout=timeout,
            impersonate="chrome131",
        )
    finally:
        try:
            multipart.close()
        except Exception:
            pass
    body = resp.text or ""
    if resp.status_code >= 400:
        try:
            err_payload = resp.json()
            err = err_payload.get("error") if isinstance(err_payload, dict) else None
            if isinstance(err, dict):
                raise RuntimeError(
                    f"import failed HTTP {resp.status_code}: {err.get('code')}: {err.get('message')}"
                )
        except RuntimeError:
            raise
        except Exception:
            pass
        raise RuntimeError(
            f"import failed HTTP {resp.status_code}: {body[:300] or resp.reason}"
        )

    complete: dict[str, Any] | None = None
    last_error: str | None = None
    for event, data in _parse_sse_events(body):
        if event == "complete":
            try:
                complete = json.loads(data) if data else {}
            except Exception as exc:
                raise RuntimeError(
                    f"invalid complete event: {exc}: {data[:200]}"
                ) from exc
        elif event == "error":
            try:
                err_obj = json.loads(data) if data else {}
            except Exception:
                err_obj = {"message": data}
            code = err_obj.get("code") if isinstance(err_obj, dict) else ""
            message = err_obj.get("message") if isinstance(err_obj, dict) else data
            last_error = f"{code or 'authImportFailed'}: {message or data}"
        elif event == "progress":
            try:
                prog = json.loads(data) if data else {}
            except Exception:
                prog = {}
            if isinstance(prog, dict) and prog.get("total"):
                _log(
                    log,
                    f"progress phase={prog.get('phase') or '-'} "
                    f"{prog.get('completed')}/{prog.get('total')}",
                )

    if last_error and complete is None:
        raise RuntimeError(f"import stream error: {last_error}")
    if complete is None:
        raise RuntimeError(f"import stream missing complete event: {body[:300]}")

    result = {
        "created": int(complete.get("created") or 0),
        "updated": int(complete.get("updated") or 0),
        "synced": int(complete.get("synced") or 0),
        "syncFailed": int(
            complete.get("syncFailed") or complete.get("sync_failed") or 0
        ),
        "skipped": int(complete.get("skipped") or 0),
    }
    _log(
        log,
        f"import done created={result['created']} updated={result['updated']} "
        f"synced={result['synced']} syncFailed={result['syncFailed']}",
    )
    return result


def import_build_accounts(
    base_url: str,
    access_token: str,
    accounts: list[dict] | dict,
    *,
    timeout: float = 180,
    log: LogFn | None = None,
    filename: str = "build-accounts.json",
) -> dict[str, int]:
    return _import_provider_accounts(
        base_url, access_token, accounts, provider="grok_build", timeout=timeout,
        log=log, filename=filename,
    )


def import_web_accounts(
    base_url: str,
    access_token: str,
    accounts: list[dict] | dict,
    *,
    timeout: float = 180,
    log: LogFn | None = None,
    filename: str = "web-accounts.json",
) -> dict[str, int]:
    return _import_provider_accounts(
        base_url, access_token, accounts, provider="grok_web", timeout=timeout,
        log=log, filename=filename,
    )


def import_console_accounts(
    base_url: str,
    access_token: str,
    accounts: list[dict] | dict,
    *,
    timeout: float = 180,
    log: LogFn | None = None,
    filename: str = "console-accounts.json",
) -> dict[str, int]:
    return _import_provider_accounts(
        base_url, access_token, accounts, provider="grok_console", timeout=timeout,
        log=log, filename=filename,
    )


def sso_account_entry(provider: str, sso_token: str, email: str = "") -> dict:
    """Create a native Grok Web/Console import entry from a registration SSO.

    The exact same SSO must be used for both providers. grok2api derives
    ``sso:<hash>`` and ``console-sso:<hash>`` source keys from it and links the
    two records during import.
    """
    provider = str(provider or "").strip().lower()
    if provider not in {"grok_web", "grok_console"}:
        raise ValueError("SSO import provider must be grok_web or grok_console")
    sso = str(sso_token or "").strip()
    if sso.lower().startswith("sso="):
        sso = sso[4:].strip()
    if not sso:
        raise ValueError("sso_token is empty")
    entry = {"provider": provider, "sso_token": sso}
    email = str(email or "").strip()
    if email:
        entry["email"] = email
        entry["name"] = f"Grok {'Web' if provider == 'grok_web' else 'Console'} {email}"
    return entry


def is_retriable_upload_error(exc: BaseException | str) -> bool:
    """Network/transient upload failures worth retrying."""
    msg = str(exc or "").strip().lower()
    if not msg:
        return False
    permanent_markers = (
        "http 400",
        "http 401",
        "http 403",
        "http 404",
        "http 409",
        "http 422",
        "unauthorized",
        "invalid credentials",
        "missing access",
        "no accounts to import",
    )
    if any(marker in msg for marker in permanent_markers):
        return False
    retriable_markers = (
        "curl:",
        "empty reply",
        "failed to perform",
        "timeout",
        "timed out",
        "connection",
        "connect",
        "reset by peer",
        "broken pipe",
        "temporarily unavailable",
        "proxy",
        "ssl",
        "tls",
        "recv failure",
        "send failure",
        "http 408",
        "http 425",
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "http 520",
        "http 521",
        "http 522",
        "http 523",
        "http 524",
        "bad gateway",
        "gateway timeout",
        "service unavailable",
        "import stream missing complete event",
        "import stream error",
    )
    return any(marker in msg for marker in retriable_markers)


def _retry_admin_import(
    do_import,
    *,
    retries: int = 3,
    retry_delay_s: float = 2.0,
    log: LogFn | None = None,
    label: str = "upload",
) -> dict[str, int]:
    try:
        extra = max(0, int(retries))
    except (TypeError, ValueError):
        extra = 3
    try:
        delay = max(0.0, float(retry_delay_s))
    except (TypeError, ValueError):
        delay = 2.0
    total = 1 + extra
    last_exc: BaseException | None = None
    for attempt in range(1, total + 1):
        try:
            result = do_import(False)
            if attempt > 1:
                _log(log, f"{label} retry OK attempt={attempt}/{total}")
            return result
        except Exception as exc:
            last_exc = exc
            msg = str(exc).lower()
            if isinstance(exc, RuntimeError) and ("401" in msg or "unauthorized" in msg):
                _log(log, f"{label} access token rejected, re-login and retry import")
                try:
                    result = do_import(True)
                    if attempt > 1:
                        _log(log, f"{label} retry OK attempt={attempt}/{total}")
                    return result
                except Exception as relogin_exc:
                    last_exc = relogin_exc
                    exc = relogin_exc
            if attempt >= total or not is_retriable_upload_error(exc):
                break
            wait_s = delay * attempt
            _log(log, f"{label} failed attempt={attempt}/{total}, retry in {wait_s:.1f}s: {exc}")
            if wait_s > 0:
                time.sleep(wait_s)
    assert last_exc is not None
    raise last_exc


def upload_build_accounts(
    base_url: str,
    username: str,
    password: str,
    entries: list[dict],
    *,
    timeout: float = 180,
    log: LogFn | None = None,
    retries: int = 3,
    retry_delay_s: float = 2.0,
    filename: str = "build-accounts.json",
) -> dict[str, int]:
    accounts: list[dict] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        access = str(entry.get("access_token") or "").strip()
        refresh = str(entry.get("refresh_token") or "").strip()
        if access or refresh:
            accounts.append(entry)
    if not accounts:
        raise ValueError("no Build accounts to import")
    timeout = max(float(timeout or 180), min(600.0, 12.0 * len(accounts)))

    def _do(force_login: bool = False) -> dict[str, int]:
        token = get_access_token(
            base_url,
            username,
            password,
            force=force_login,
            timeout=min(timeout, 60),
            log=log,
        )
        return import_build_accounts(
            base_url,
            token,
            accounts,
            timeout=timeout,
            log=log,
            filename=filename or "build-accounts.json",
        )

    return _retry_admin_import(
        _do, retries=retries, retry_delay_s=retry_delay_s, log=log, label="Build"
    )


def upload_build_account(
    base_url: str,
    username: str,
    password: str,
    entry: dict,
    *,
    timeout: float = 180,
    log: LogFn | None = None,
    retries: int = 3,
    retry_delay_s: float = 2.0,
) -> dict[str, int]:
    if not isinstance(entry, dict):
        raise ValueError("entry must be a dict")
    email = str(
        entry.get("email") or entry.get("name") or entry.get("user_id") or "account"
    ).strip()
    safe_name = "".join(
        ch if ch.isalnum() or ch in "._-@" else "_" for ch in email
    )[:80] or "account"
    return upload_build_accounts(
        base_url,
        username,
        password,
        [entry],
        timeout=timeout,
        log=log,
        retries=retries,
        retry_delay_s=retry_delay_s,
        filename=f"{safe_name}.json",
    )


def upload_sso_accounts(
    base_url: str,
    username: str,
    password: str,
    *,
    provider: str,
    items: list[dict],
    timeout: float = 180,
    log: LogFn | None = None,
    retries: int = 3,
    retry_delay_s: float = 2.0,
    filename: str = "",
) -> dict[str, int]:
    provider = str(provider or "").strip().lower()
    importers = {
        "grok_web": import_web_accounts,
        "grok_console": import_console_accounts,
    }
    try:
        importer = importers[provider]
    except KeyError as exc:
        raise ValueError("provider must be grok_web or grok_console") from exc
    entries = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        sso = str(item.get("sso_token") or item.get("sso") or "").strip()
        if not sso:
            continue
        entries.append(sso_account_entry(provider, sso, str(item.get("email") or "")))
    if not entries:
        raise ValueError("no SSO accounts to import")
    label = "web" if provider == "grok_web" else "console"
    timeout = max(float(timeout or 180), min(600.0, 8.0 * len(entries)))
    fname = filename or f"{label}-accounts.json"

    def _do(force_login: bool = False) -> dict[str, int]:
        token = get_access_token(
            base_url,
            username,
            password,
            force=force_login,
            timeout=min(timeout, 60),
            log=log,
        )
        return importer(
            base_url,
            token,
            entries,
            timeout=timeout,
            log=log,
            filename=fname,
        )

    return _retry_admin_import(
        _do, retries=retries, retry_delay_s=retry_delay_s, log=log, label=label
    )


def upload_sso_account(
    base_url: str,
    username: str,
    password: str,
    *,
    provider: str,
    sso_token: str,
    email: str = "",
    timeout: float = 180,
    log: LogFn | None = None,
    retries: int = 3,
    retry_delay_s: float = 2.0,
) -> dict[str, int]:
    """Upload one registration SSO to Grok Web or Console with retries."""
    label = "web" if str(provider or "").strip().lower() == "grok_web" else "console"
    safe_email = str(email or "account").strip()
    safe_name = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in safe_email)[:80] or "account"
    return upload_sso_accounts(
        base_url,
        username,
        password,
        provider=provider,
        items=[{"sso_token": sso_token, "email": email}],
        timeout=timeout,
        log=log,
        retries=retries,
        retry_delay_s=retry_delay_s,
        filename=f"{label}-{safe_name}.json",
    )


def clear_token_cache() -> None:
    with _token_lock:
        _token_cache["access_token"] = ""
        _token_cache["expires_at"] = 0.0
        _token_cache["base_url"] = ""
        _token_cache["username"] = ""


DEFAULT_UPLOAD_PENDING_FILE = "grok2api_upload_pending.json"
DEFAULT_SSO_UPLOAD_PENDING_FILES = {
    "grok_web": "grok2api_upload_pending_web.json",
    "grok_console": "grok2api_upload_pending_console.json",
}
_pending_locks: dict[str, threading.Lock] = {}
_pending_locks_guard = threading.Lock()


def _lock_for_path(path: Path) -> threading.Lock:
    try:
        key = str(path.resolve())
    except OSError:
        key = str(path)
    with _pending_locks_guard:
        lock = _pending_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _pending_locks[key] = lock
        return lock


def _decode_jwt_payload(token: str) -> dict:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + ("=" * ((4 - len(parts[1]) % 4) % 4))
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def token_to_grok2api_account(token: dict, email: str = "") -> dict:
    """OAuth token dict → grok2api Build import entry."""
    access = str(token.get("access_token") or token.get("key") or "").strip()
    refresh = str(token.get("refresh_token") or "").strip()
    id_token = str(token.get("id_token") or "").strip()
    payload = _decode_jwt_payload(access) if access else {}
    id_payload = _decode_jwt_payload(id_token) if id_token else {}
    resolved_email = (
        str(email or "").strip()
        or str(id_payload.get("email") or "").strip()
        or str(payload.get("email") or "").strip()
    )
    user_id = str(
        payload.get("sub")
        or id_payload.get("sub")
        or payload.get("principal_id")
        or id_payload.get("principal_id")
        or ""
    ).strip()
    team_id = str(payload.get("team_id") or id_payload.get("team_id") or "").strip()
    expires_at = ""
    if "exp" in payload:
        try:
            expires_at = datetime.fromtimestamp(
                int(payload["exp"]), tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError, OSError):
            expires_at = ""
    if not expires_at and token.get("expires_in") is not None:
        try:
            expires_at = datetime.fromtimestamp(
                int(time.time()) + int(token["expires_in"]), tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError, OSError):
            expires_at = ""
    entry: dict = {
        "provider": "grok_build",
        "name": resolved_email or user_id or "Grok Build account",
        "client_id": GROK_BUILD_CLIENT_ID,
        "access_token": access,
        "refresh_token": refresh,
        "token_type": str(token.get("token_type") or "Bearer"),
        "email": resolved_email,
        "user_id": user_id,
    }
    bot_flag_source = payload.get("bot_flag_source", id_payload.get("bot_flag_source"))
    if bot_flag_source is not None:
        entry["bot_flag_source"] = bot_flag_source
    try:
        entry["build_bot_flagged"] = int(bot_flag_source) == 1
    except (TypeError, ValueError):
        entry["build_bot_flagged"] = False
    if id_token:
        entry["id_token"] = id_token
    if team_id:
        entry["team_id"] = team_id
    if expires_at:
        entry["expires_at"] = expires_at
    if token.get("expires_in") is not None:
        try:
            entry["expires_in"] = int(token["expires_in"])
        except (TypeError, ValueError):
            pass
    return entry


def _account_identity_keys(entry: dict) -> set[str]:
    keys: set[str] = set()
    email = str(entry.get("email") or "").strip().casefold()
    if email:
        keys.add(f"email:{email}")
    user_id = str(entry.get("user_id") or entry.get("principal_id") or "").strip()
    if user_id:
        keys.add(f"user:{user_id}")
    return keys


def _upsert_account(accounts: list[dict], entry: dict) -> None:
    index: dict[str, int] = {}
    for i, item in enumerate(accounts):
        if not isinstance(item, dict):
            continue
        for key in _account_identity_keys(item):
            index[key] = i
    target = None
    for key in _account_identity_keys(entry):
        if key in index:
            target = index[key]
            break
    if target is None:
        accounts.append(entry)
    else:
        accounts[target] = entry


def _write_accounts_document(path: Path, accounts: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"accounts": accounts}, indent=2, ensure_ascii=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def resolve_upload_pending_path(
    path: Path | str | None = None,
    *,
    base_dir: Path | str | None = None,
) -> Path:
    root = Path(base_dir) if base_dir is not None else Path(__file__).resolve().parent
    if path is not None and str(path).strip():
        candidate = Path(str(path).strip())
        if candidate.is_absolute():
            return candidate
        return (root / candidate).resolve()
    return (root / DEFAULT_UPLOAD_PENDING_FILE).resolve()


def save_upload_pending(
    entry: dict,
    path: Path | str | None = None,
    *,
    base_dir: Path | str | None = None,
    error: str = "",
) -> Path:
    if not isinstance(entry, dict):
        raise ValueError("entry must be a dict")
    if not (
        str(entry.get("access_token") or "").strip()
        or str(entry.get("refresh_token") or "").strip()
    ):
        raise ValueError("entry missing access_token/refresh_token")
    out = resolve_upload_pending_path(path, base_dir=base_dir)
    payload = dict(entry)
    if error:
        payload["upload_error"] = str(error)[:500]
        payload["upload_failed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lock = _lock_for_path(out)
    with lock:
        accounts: list[dict] = []
        if out.is_file():
            try:
                raw = json.loads(out.read_text(encoding="utf-8"))
                found = raw.get("accounts") if isinstance(raw, dict) else raw
                if isinstance(found, list):
                    accounts = [item for item in found if isinstance(item, dict)]
            except (OSError, ValueError, TypeError):
                accounts = []
        _upsert_account(accounts, payload)
        _write_accounts_document(out, accounts)
    return out


def save_sso_upload_pending(
    provider: str,
    sso_token: str,
    email: str = "",
    *,
    base_dir: Path | str | None = None,
    error: str = "",
) -> Path:
    provider = str(provider or "").strip().lower()
    try:
        filename = DEFAULT_SSO_UPLOAD_PENDING_FILES[provider]
    except KeyError as exc:
        raise ValueError("provider must be grok_web or grok_console") from exc
    token = str(sso_token or "").strip()
    if token.lower().startswith("sso="):
        token = token[4:].strip()
    if not token:
        raise ValueError("sso_token is empty")
    root = Path(base_dir) if base_dir is not None else Path(__file__).resolve().parent
    out = (root / filename).resolve()
    label = "Web" if provider == "grok_web" else "Console"
    entry = {
        "name": f"Grok {label} {str(email or '').strip()}".strip(),
        "email": str(email or "").strip(),
        "sso_token": token,
    }
    if error:
        entry["upload_error"] = str(error)[:500]
        entry["upload_failed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lock = _lock_for_path(out)
    with lock:
        accounts: list[dict] = []
        if out.is_file():
            try:
                raw = json.loads(out.read_text(encoding="utf-8"))
                found = raw.get("accounts") if isinstance(raw, dict) else raw
                if isinstance(found, list):
                    accounts = [item for item in found if isinstance(item, dict)]
            except (OSError, ValueError, TypeError):
                accounts = []
        replaced = False
        for index, old in enumerate(accounts):
            if isinstance(old, dict) and str(old.get("sso_token") or "").strip() == token:
                accounts[index] = entry
                replaced = True
                break
        if not replaced:
            accounts.append(entry)
        _write_accounts_document(out, accounts)
    return out
