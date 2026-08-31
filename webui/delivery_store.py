# -*- coding: utf-8 -*-
"""CPA / grok2api delivery settings stored in config.json."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from secure_files import atomic_write_json, exclusive_file_lock
from webui.security_utils import redact_log_line


ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.environ.get("DELIVERY_CONFIG_FILE", str(ROOT / "config.json")))
LOCK_PATH = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".lock")

TOKEN_MODES = ("device_protocol", "device_browser", "auth_code")
TOKEN_MODE_LABELS = {
    "device_protocol": "协议 Device Flow",
    "device_browser": "浏览器 Device Flow",
    "auth_code": "Authorization Code",
}

BOOL_FIELDS = (
    "cpa_auto_add",
    "grok2api_auto_upload",
    "grok2api_upload_web",
    "grok2api_upload_console",
)
SECRET_FIELDS = ("cpa_management_key", "grok2api_admin_password")
INT_FIELDS = ("grok2api_upload_retries",)
FLOAT_FIELDS = ("grok2api_upload_retry_delay_s",)
STRING_FIELDS = (
    "cpa_token_mode",
    "cpa_auth_dir",
    "cpa_remote_url",
    "grok2api_auth_dir",
    "grok2api_base_url",
    "grok2api_admin_user",
    "grok2api_upload_pending_file",
)
ALL_FIELDS = BOOL_FIELDS + SECRET_FIELDS + INT_FIELDS + FLOAT_FIELDS + STRING_FIELDS

DEFAULTS = {
    "cpa_auto_add": False,
    "cpa_token_mode": "device_protocol",
    "cpa_auth_dir": "cpa_auth",
    "cpa_remote_url": "",
    "cpa_management_key": "",
    "grok2api_auth_dir": "grok2api_auth",
    "grok2api_auto_upload": False,
    "grok2api_upload_web": False,
    "grok2api_upload_console": False,
    "grok2api_base_url": "",
    "grok2api_admin_user": "admin",
    "grok2api_admin_password": "",
    "grok2api_upload_retries": 3,
    "grok2api_upload_retry_delay_s": 2.0,
    "grok2api_upload_pending_file": "grok2api_upload_pending.json",
}


class DeliveryConfigError(ValueError):
    """Invalid delivery settings payload."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_unlocked() -> tuple[dict, str]:
    if not CONFIG_PATH.exists():
        return {}, ""
    try:
        import json

        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, redact_log_line(str(exc))
    if not isinstance(raw, dict):
        return {}, "config.json 不是 JSON 对象"
    return raw, ""


def _bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    return default


def _int(value: object, default: int, lo: int, hi: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(lo, min(hi, number))


def _float(value: object, default: float, lo: float, hi: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return max(lo, min(hi, number))


def _merged(raw: dict) -> dict:
    values = dict(DEFAULTS)
    for name in ALL_FIELDS:
        if name in raw:
            values[name] = raw[name]
    values["cpa_auto_add"] = _bool(values.get("cpa_auto_add"), False)
    values["grok2api_auto_upload"] = _bool(values.get("grok2api_auto_upload"), False)
    values["grok2api_upload_web"] = _bool(values.get("grok2api_upload_web"), False)
    values["grok2api_upload_console"] = _bool(values.get("grok2api_upload_console"), False)
    mode = str(values.get("cpa_token_mode") or "device_protocol").strip().lower()
    values["cpa_token_mode"] = mode if mode in TOKEN_MODES else "device_protocol"
    values["cpa_auth_dir"] = str(values.get("cpa_auth_dir") or "cpa_auth").strip() or "cpa_auth"
    values["cpa_remote_url"] = str(values.get("cpa_remote_url") or "").strip()
    values["cpa_management_key"] = str(values.get("cpa_management_key") or "")
    values["grok2api_auth_dir"] = (
        str(values.get("grok2api_auth_dir") or "grok2api_auth").strip() or "grok2api_auth"
    )
    values["grok2api_base_url"] = str(values.get("grok2api_base_url") or "").strip()
    values["grok2api_admin_user"] = (
        str(values.get("grok2api_admin_user") or "admin").strip() or "admin"
    )
    values["grok2api_admin_password"] = str(values.get("grok2api_admin_password") or "")
    values["grok2api_upload_retries"] = _int(values.get("grok2api_upload_retries"), 3, 0, 10)
    values["grok2api_upload_retry_delay_s"] = _float(
        values.get("grok2api_upload_retry_delay_s"), 2.0, 0.0, 30.0
    )
    values["grok2api_upload_pending_file"] = (
        str(values.get("grok2api_upload_pending_file") or "grok2api_upload_pending.json").strip()
        or "grok2api_upload_pending.json"
    )
    return values


def _public_state(raw: dict, error: str = "") -> dict:
    values = _merged(raw)
    public = dict(values)
    for name in SECRET_FIELDS:
        public[name] = ""
    try:
        mtime = CONFIG_PATH.stat().st_mtime
    except OSError:
        mtime = None
    ready = bool(
        values["grok2api_auto_upload"]
        and values["grok2api_base_url"]
        and values["grok2api_admin_user"]
        and values["grok2api_admin_password"]
    )
    return {
        "ok": not error,
        "error": error or None,
        "values": public,
        "secret_configured": {name: bool(values.get(name)) for name in SECRET_FIELDS},
        "token_modes": [
            {"id": mode, "label": TOKEN_MODE_LABELS[mode]} for mode in TOKEN_MODES
        ],
        "upload_ready": ready,
        "config_exists": CONFIG_PATH.exists(),
        "mtime": mtime,
    }


def read_delivery_config() -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
    return _public_state(raw, error)


def _normalize_url(value: object, *, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise DeliveryConfigError(f"{field} 不是有效的 http(s) 地址")
    return text.rstrip("/")


def _candidate_config(raw: dict, settings: object, clear_secrets: object = None) -> dict:
    if not isinstance(settings, dict):
        raise DeliveryConfigError("settings 必须是 JSON 对象")
    unknown = sorted(set(settings) - set(ALL_FIELDS))
    if unknown:
        raise DeliveryConfigError(f"包含不支持的配置字段: {unknown[0]}")
    if clear_secrets is None:
        clear = set()
    elif isinstance(clear_secrets, list):
        clear = {str(item or "").strip() for item in clear_secrets}
    else:
        raise DeliveryConfigError("clear_secrets 必须是数组")
    if not clear <= set(SECRET_FIELDS):
        raise DeliveryConfigError("包含不支持的密钥清除字段")

    updated = dict(raw)
    current = _merged(raw)
    for name, value in settings.items():
        if name in SECRET_FIELDS and not str(value or ""):
            continue
        if name in BOOL_FIELDS:
            updated[name] = _bool(value, current[name])
        elif name == "cpa_token_mode":
            mode = str(value or "").strip().lower()
            if mode not in TOKEN_MODES:
                raise DeliveryConfigError("cpa_token_mode 无效")
            updated[name] = mode
        elif name == "cpa_remote_url":
            updated[name] = _normalize_url(value, field="cpa_remote_url")
        elif name == "grok2api_base_url":
            updated[name] = _normalize_url(value, field="grok2api_base_url")
        elif name in INT_FIELDS:
            updated[name] = _int(value, current[name], 0, 10)
        elif name in FLOAT_FIELDS:
            updated[name] = _float(value, current[name], 0.0, 30.0)
        else:
            updated[name] = str(value or "").strip()
    for name in clear:
        updated[name] = ""
    if str(updated.get("grok2api_admin_user") or "").strip() == "":
        updated["grok2api_admin_user"] = "admin"
    return updated


def save_delivery_config(settings: object, *, clear_secrets: object = None) -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
        if error:
            raise RuntimeError(f"config.json 无法读取: {error}")
        updated = _candidate_config(raw, settings, clear_secrets)
        atomic_write_json(CONFIG_PATH, updated)
    result = _public_state(updated)
    result["saved_at"] = _utc_now()
    return result


def test_delivery_config(settings: object, *, clear_secrets: object = None) -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
    if error:
        raise RuntimeError(f"config.json 无法读取: {error}")
    candidate = _merged(_candidate_config(raw, settings, clear_secrets))
    base = str(candidate.get("grok2api_base_url") or "").strip()
    user = str(candidate.get("grok2api_admin_user") or "").strip()
    password = str(candidate.get("grok2api_admin_password") or "")
    if not base:
        raise DeliveryConfigError("请先填写 grok2api 地址")
    if not user or not password:
        raise DeliveryConfigError("请先填写 grok2api 管理员用户和密码")
    import grok2api_client as g2a

    g2a.clear_token_cache()
    g2a.login_admin(base, user, password, timeout=20)
    return {
        "ok": True,
        "detail": f"管理员登录成功 {g2a.normalize_base_url(base)}",
        "base_url": g2a.normalize_base_url(base),
    }
