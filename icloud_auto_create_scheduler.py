#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""In-process scheduler for pre-creating iCloud Hide My Email aliases."""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional


MIN_INTERVAL_MINUTES = 1
MAX_INTERVAL_MINUTES = 24 * 60
MIN_BATCH_SIZE = 1
MAX_BATCH_SIZE = 20
POLL_SECONDS = 2.0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


class ICloudAutoCreateScheduler:
    """Runs one iCloud alias batch at a time and records lightweight runtime state."""

    def __init__(
        self,
        config_getter: Callable[[], Dict[str, Any]],
        create_batch: Callable[[int, Callable[[str], None]], Dict[str, Any]],
        *,
        enabled_key: str = "icloud_auto_create_enabled",
        interval_key: str = "icloud_auto_create_interval_minutes",
        batch_key: str = "icloud_auto_create_batch_size",
        default_interval: int = 60,
        default_batch: int = 1,
        max_batch: int = MAX_BATCH_SIZE,
        verb: str = "创建",
        thread_name: str = "icloud-auto-create",
    ):
        self._config_getter = config_getter
        self._create_batch = create_batch
        self._enabled_key = enabled_key
        self._interval_key = interval_key
        self._batch_key = batch_key
        self._default_interval = default_interval
        self._default_batch = default_batch
        self._max_batch = max_batch
        self._verb = verb
        self._thread_name = thread_name
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._run_now_requested = False
        self._next_run_at: Optional[datetime] = None
        self._last_started_at: Optional[datetime] = None
        self._last_finished_at: Optional[datetime] = None
        self._last_status = "idle"
        self._last_error = ""
        self._last_result: Dict[str, Any] = {}
        self._today_date = datetime.now().date().isoformat()
        self._today_total = 0
        self._recent_success = deque(maxlen=10)
        self._logs = deque(maxlen=100)

    def _schedule(self) -> Dict[str, Any]:
        config = self._config_getter() or {}
        return {
            "enabled": bool(config.get(self._enabled_key, False)),
            "interval_minutes": _as_int(
                config.get(self._interval_key, self._default_interval),
                MIN_INTERVAL_MINUTES,
                MAX_INTERVAL_MINUTES,
                self._default_interval,
            ),
            "batch_size": _as_int(
                config.get(self._batch_key, self._default_batch),
                MIN_BATCH_SIZE,
                self._max_batch,
                self._default_batch,
            ),
        }

    def _append_log_locked(self, level: str, message: str) -> None:
        self._logs.append(
            {
                "time": _utc_now().isoformat(),
                "level": str(level or "info"),
                "message": str(message or "").strip(),
            }
        )

    def _roll_today_locked(self) -> None:
        today = datetime.now().date().isoformat()
        if self._today_date != today:
            self._today_date = today
            self._today_total = 0

    def snapshot(self) -> Dict[str, Any]:
        schedule = self._schedule()
        with self._lock:
            self._roll_today_locked()
            return {
                **schedule,
                "running": self._running,
                "run_now_requested": self._run_now_requested,
                "next_run_at": self._next_run_at.isoformat() if self._next_run_at else None,
                "last_started_at": self._last_started_at.isoformat() if self._last_started_at else None,
                "last_finished_at": self._last_finished_at.isoformat() if self._last_finished_at else None,
                "last_status": self._last_status,
                "last_error": self._last_error,
                "last_result": dict(self._last_result),
                "today_total_records": self._today_total,
                "recent_success_records": list(self._recent_success),
                "logs": list(self._logs),
            }

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name=self._thread_name,
            )
            self._thread.start()
        self.notify_schedule_updated()

    def shutdown(self) -> None:
        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=3)

    def notify_schedule_updated(self) -> Dict[str, Any]:
        schedule = self._schedule()
        now = _utc_now()
        with self._lock:
            if not schedule["enabled"] and not self._running:
                self._next_run_at = None
                self._run_now_requested = False
                self._append_log_locked("info", f"iCloud 定时{self._verb}已禁用")
            elif schedule["enabled"] and not self._running:
                self._next_run_at = now + timedelta(minutes=schedule["interval_minutes"])
                self._append_log_locked(
                    "info",
                    f"iCloud 定时{self._verb}已启用：每 {schedule['interval_minutes']} 分钟{self._verb} {schedule['batch_size']} 个",
                )
        return self.snapshot()

    def request_run_now(self) -> Dict[str, Any]:
        with self._lock:
            self._run_now_requested = True
            if not self._running:
                self._next_run_at = _utc_now()
            self._append_log_locked("info", f"已请求立即{self._verb} iCloud 邮箱")
        return self.snapshot()

    def _run_loop(self) -> None:
        while not self._stop_event.wait(POLL_SECONDS):
            self.tick()

    def tick(self) -> None:
        schedule = self._schedule()
        now = _utc_now()
        with self._lock:
            if not schedule["enabled"] and not self._run_now_requested:
                if not self._running:
                    self._next_run_at = None
                return
            if self._running:
                return
            if self._next_run_at is None:
                self._next_run_at = now + timedelta(minutes=schedule["interval_minutes"])
                return
            if not self._run_now_requested and now < self._next_run_at:
                return
            reason = "manual" if self._run_now_requested else "scheduled"
            self._running = True
            self._run_now_requested = False
            self._last_status = "running"
            self._last_error = ""
            self._last_result = {}
            self._last_started_at = now
            self._last_finished_at = None
            self._append_log_locked("info", f"开始 iCloud 定时{self._verb}（{reason}）")
        threading.Thread(
            target=self._execute,
            args=(schedule["batch_size"], reason),
            daemon=True,
            name="icloud-auto-create-batch",
        ).start()

    def _execute(self, batch_size: int, reason: str) -> None:
        try:
            result = self._create_batch(
                batch_size,
                lambda message: self._log_from_batch(message),
            )
            created = int(result.get("created_count") or result.get("deleted_count") or 0)
            failed = int(result.get("failed_count") or 0)
            status = "success" if failed == 0 else ("partial" if created else "failed")
            error = "; ".join(str(item) for item in (result.get("errors") or [])[:3])
        except Exception as exc:
            result = {"created_count": 0, "failed_count": 1, "errors": [str(exc)]}
            created, failed, status, error = 0, 1, "failed", str(exc)

        now = _utc_now()
        schedule = self._schedule()
        with self._lock:
            self._roll_today_locked()
            self._running = False
            self._last_finished_at = now
            self._last_status = status
            self._last_error = error
            self._last_result = dict(result)
            self._next_run_at = (
                now + timedelta(minutes=schedule["interval_minutes"])
                if schedule["enabled"]
                else None
            )
            for email in result.get("emails") or []:
                self._recent_success.appendleft(
                    {"time": now.isoformat(), "email": str(email), "source": f"auto:{reason}"}
                )
            self._today_total += created
            if status == "success":
                self._append_log_locked("success", f"本次{self._verb}完成：处理 {created} 个")
            elif status == "partial":
                self._append_log_locked("warning", f"本次部分成功：处理 {created} 个，失败 {failed} 个")
            else:
                self._append_log_locked("error", f"本次{self._verb}失败：{error or 'unknown_error'}")

    def _log_from_batch(self, message: str) -> None:
        with self._lock:
            self._append_log_locked("info", message)
