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
    if not cookies:
        raise ValueError("请先配置 iCloud Cookies")
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


def _create_batch(count: int, log_callback) -> Dict[str, Any]:
    service = _inventory_service()
    return service.create_free_aliases(count, log_callback=log_callback)


SCHEDULER = ICloudAutoCreateScheduler(_raw_config, _create_batch)


def start_scheduler() -> None:
    SCHEDULER.start()


def notify_config_updated() -> Dict[str, Any]:
    return SCHEDULER.notify_schedule_updated()


def runtime_snapshot() -> Dict[str, Any]:
    return {"ok": True, "runtime": SCHEDULER.snapshot()}


def request_run_now() -> Dict[str, Any]:
    return {"ok": True, "runtime": SCHEDULER.request_run_now()}


def inventory_snapshot() -> Dict[str, Any]:
    try:
        service = _inventory_service()
        return {
            "ok": True,
            "stats": service.stats(),
            "aliases": service.list_aliases(),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": redact_log_line(str(exc))[:300],
            "stats": {},
            "aliases": [],
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
        },
    }
