"""Pause after every N successful registrations in the current task."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Callable, Mapping

from retry_policy import bounded_env_int
from secure_files import atomic_write_json, ensure_private_dir

LogFn = Callable[[str], None]

COOLDOWN_EVERY_DEFAULT = 0
COOLDOWN_SECONDS_DEFAULT = 60
_STATE_NAME = "task_cooldown.json"
_LOCK = threading.RLock()


def cooldown_every(environ: Mapping[str, str] | None = None) -> int:
    return bounded_env_int(
        "GROK_TASK_COOLDOWN_EVERY",
        COOLDOWN_EVERY_DEFAULT,
        minimum=0,
        maximum=2000,
        environ=environ,
    )


def cooldown_seconds(environ: Mapping[str, str] | None = None) -> int:
    return bounded_env_int(
        "GROK_TASK_COOLDOWN_SECONDS",
        COOLDOWN_SECONDS_DEFAULT,
        minimum=0,
        maximum=86400,
        environ=environ,
    )


def cooldown_state_path(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    raw = str(env.get("GROK_TASK_COOLDOWN_FILE", "") or "").strip()
    if raw:
        return Path(raw)
    return Path(__file__).resolve().parent / "log" / _STATE_NAME


def _empty_state(environ: Mapping[str, str] | None = None) -> dict:
    return {
        "ok": 0,
        "every": cooldown_every(environ),
        "seconds": cooldown_seconds(environ),
        "pause_until": 0.0,
    }


def _load(path: Path, environ: Mapping[str, str] | None = None) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            state = _empty_state(environ)
            state["ok"] = max(0, int(data.get("ok") or 0))
            state["pause_until"] = max(0.0, float(data.get("pause_until") or 0))
            return state
    except Exception:
        pass
    return _empty_state(environ)


def _save(path: Path, state: dict) -> None:
    ensure_private_dir(path.parent)
    atomic_write_json(
        path,
        {
            "ok": int(state.get("ok") or 0),
            "every": int(state.get("every") or 0),
            "seconds": int(state.get("seconds") or 0),
            "pause_until": float(state.get("pause_until") or 0),
        },
    )


def reset_task_cooldown(environ: Mapping[str, str] | None = None) -> dict:
    path = cooldown_state_path(environ)
    state = _empty_state(environ)
    with _LOCK:
        _save(path, state)
    return state


def note_task_success(
    now: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[int, float]:
    """Record one success. Returns (ok_count, wait_seconds_if_triggered)."""
    ts = time.time() if now is None else float(now)
    path = cooldown_state_path(environ)
    with _LOCK:
        state = _load(path, environ)
        state["ok"] = int(state.get("ok") or 0) + 1
        every = int(state.get("every") or 0)
        seconds = int(state.get("seconds") or 0)
        wait = 0.0
        if every > 0 and seconds > 0 and state["ok"] % every == 0:
            wait = float(seconds)
            state["pause_until"] = ts + wait
        _save(path, state)
        return state["ok"], wait


def remaining_task_cooldown(
    now: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[int, float]:
    ts = time.time() if now is None else float(now)
    path = cooldown_state_path(environ)
    with _LOCK:
        state = _load(path, environ)
        wait = max(0.0, float(state.get("pause_until") or 0) - ts)
        return int(state.get("ok") or 0), wait


def apply_task_cooldown_wait(
    log: LogFn | None,
    should_stop: Callable[[], bool] | None,
    sleep_fn: Callable[[float, Callable[[], bool] | None], None],
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Wait out a success-count cooldown. True means the caller should stop."""
    ok, wait = remaining_task_cooldown(environ=environ)
    if wait <= 0:
        return bool(should_stop and should_stop())
    if log:
        log(f"[冷却] 本任务已成功 {ok} 个，暂停 {wait:.0f}s 后再继续")
    sleep_fn(wait, should_stop)
    return bool(should_stop and should_stop())
