"""iCloud Hide My Email inventory and auto-create helpers for the live panel."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from icloud_auto_create_scheduler import ICloudAutoCreateScheduler
from webui.email_provider_store import CONFIG_PATH
from webui.security_utils import redact_log_line

try:
    from email_providers import icloud_pool as alias_pool
except ImportError:  # pragma: no cover
    alias_pool = None  # type: ignore


def _raw_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _inventory_service(config: Optional[Dict[str, Any]] = None):
    if alias_pool is None:
        raise RuntimeError("iCloud 库存模块不可用")
    config = config or _raw_config()
    cookies = str(config.get("icloud_cookies") or "").strip()
    return alias_pool.get_lease_service(
        cookies,
        inventory_path=str(
            config.get("icloud_inventory_file") or alias_pool.DEFAULT_INVENTORY_FILE
        ),
        platform=str(config.get("icloud_platform_tag") or "grok"),
        label=str(config.get("icloud_alias_label") or "grok"),
        lease_ttl_sec=_as_float(config.get("icloud_lease_ttl_sec"), 900),
        sync_interval_sec=_as_float(config.get("icloud_sync_interval_sec"), 300),
        reuse_aliases=bool(config.get("icloud_reuse_aliases", True)),
        create_when_exhausted=bool(config.get("icloud_create_when_exhausted", True)),
        cloud_mark=bool(config.get("icloud_cloud_mark", True)),
        coordination_mode=str(config.get("icloud_coordination_mode") or "local_fast"),
        async_mark=False,
        background_replenish=False,
        low_watermark=_as_int(config.get("icloud_low_watermark"), 5),
        high_watermark=_as_int(config.get("icloud_high_watermark"), 20),
        timeout=25.0,
        auto_start_background=False,
    )


def _account_ids(config: Dict[str, Any], key: str) -> list:
    raw = config.get(key)
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return [item.strip() for item in str(raw or "").split(",") if item.strip()]


def _create_batch(count: int, log_callback) -> Dict[str, Any]:
    service = _inventory_service()
    config = _raw_config()
    return service.create_free_aliases(
        count,
        log_callback=log_callback,
        account_ids=_account_ids(config, "icloud_auto_create_account_ids"),
    )


def _delete_batch(count: int, log_callback) -> Dict[str, Any]:
    service = _inventory_service()
    config = _raw_config()
    return service.delete_registered_aliases(
        count,
        min_age_hours=_as_float(config.get("icloud_auto_delete_min_age_hours"), 0),
        keep_last=_as_int(config.get("icloud_auto_delete_keep_last"), 0),
        account_ids=_account_ids(config, "icloud_auto_delete_account_ids"),
        log_callback=log_callback,
    )


SCHEDULER = ICloudAutoCreateScheduler(_raw_config, _create_batch)
DELETE_SCHEDULER = ICloudAutoCreateScheduler(
    _raw_config,
    _delete_batch,
    enabled_key="icloud_auto_delete_enabled",
    interval_key="icloud_auto_delete_interval_minutes",
    batch_key="icloud_auto_delete_batch_size",
    default_interval=120,
    default_batch=5,
    max_batch=50,
    verb="删除",
    thread_name="icloud-auto-delete",
)


def start_scheduler() -> None:
    SCHEDULER.start()
    DELETE_SCHEDULER.start()


def notify_config_updated() -> Dict[str, Any]:
    config = _raw_config()
    cookies = str(config.get("icloud_cookies") or "").strip()
    if cookies:
        try:
            _inventory_service().add_account(cookies, name="default")
        except Exception:
            pass
    return {
        "create": SCHEDULER.notify_schedule_updated(),
        "delete": DELETE_SCHEDULER.notify_schedule_updated(),
    }


def runtime_snapshot() -> Dict[str, Any]:
    config = _raw_config()
    return {
        "ok": True,
        "runtime": SCHEDULER.snapshot(),
        "delete_runtime": DELETE_SCHEDULER.snapshot(),
        "create_account_ids": _account_ids(config, "icloud_auto_create_account_ids"),
        "delete_account_ids": _account_ids(config, "icloud_auto_delete_account_ids"),
        "delete_min_age_hours": _as_float(config.get("icloud_auto_delete_min_age_hours"), 0),
        "delete_keep_last": _as_int(config.get("icloud_auto_delete_keep_last"), 0),
    }


def request_run_now() -> Dict[str, Any]:
    runtime = SCHEDULER.request_run_now(wait=True, timeout=120)
    inventory = inventory_snapshot()
    result = runtime.get("last_result") or {}
    ok = str(runtime.get("last_status") or "") in ("success", "partial")
    error = str(runtime.get("last_error") or "")
    return {
        "ok": ok or not error,
        "error": None if ok or not error else redact_log_line(error)[:400],
        "runtime": runtime,
        "result": result,
        "inventory": inventory,
    }


def request_delete_now() -> Dict[str, Any]:
    runtime = DELETE_SCHEDULER.request_run_now(wait=True, timeout=120)
    inventory = inventory_snapshot()
    result = runtime.get("last_result") or {}
    ok = str(runtime.get("last_status") or "") in ("success", "partial")
    error = str(runtime.get("last_error") or "")
    return {
        "ok": ok or not error,
        "error": None if ok or not error else redact_log_line(error)[:400],
        "runtime": runtime,
        "result": result,
        "inventory": inventory,
    }


def inventory_snapshot() -> Dict[str, Any]:
    try:
        service = _inventory_service()
        return {
            "ok": True,
            "stats": service.stats(),
            "aliases": service.list_aliases(),
            "accounts": service.list_accounts(),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": redact_log_line(str(exc))[:300],
            "stats": {},
            "aliases": [],
            "accounts": [],
        }


def sync_inventory() -> Dict[str, Any]:
    service = _inventory_service()
    sync = service.sync(force=True)
    return {
        "ok": True,
        "inventory": {
            "sync": sync,
            "stats": service.stats(),
            "aliases": service.list_aliases(),
            "accounts": service.list_accounts(),
        },
    }


def add_account(cookies: str, name: str = "") -> Dict[str, Any]:
    service = _inventory_service()
    result = service.add_account(cookies, name=name)
    result["accounts"] = service.list_accounts()
    return result


def update_account(account_id: str, **fields) -> Dict[str, Any]:
    service = _inventory_service()
    result = service.update_account(account_id, **fields)
    result["accounts"] = service.list_accounts()
    return result


def delete_account(account_id: str) -> Dict[str, Any]:
    service = _inventory_service()
    result = service.delete_account(account_id, delete_remote=True)
    result["accounts"] = service.list_accounts()
    result["aliases"] = service.list_aliases()
    result["stats"] = service.stats()
    return result
