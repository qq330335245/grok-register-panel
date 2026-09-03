"""Consecutive registration-risk circuit breaker."""
from __future__ import annotations

import threading
import time
from typing import Callable, Mapping

from retry_policy import (
    risk_streak_stop,
    risk_streak_wait_base,
    risk_streak_wait_max,
    risk_streak_wait_start,
)

LogFn = Callable[[str], None]


class RiskCircuitBreaker:
    """Count consecutive risk rejects: wait, then stop the whole batch."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._lock = threading.Lock()
        self._environ = environ
        self.streak = 0
        self.pause_until = 0.0
        self.stopped = False
        self.reason = ""

    def reset(self) -> None:
        with self._lock:
            self.streak = 0
            self.pause_until = 0.0
            self.stopped = False
            self.reason = ""

    def note_success(self) -> None:
        with self._lock:
            self.streak = 0
            self.pause_until = 0.0

    def note_risk(self, now: float | None = None) -> tuple[str, float, int]:
        """Record one risk. Returns (ok|wait|stop, wait_seconds, streak)."""
        ts = time.time() if now is None else float(now)
        wait_start = risk_streak_wait_start(self._environ)
        stop_at = risk_streak_stop(self._environ)
        base = risk_streak_wait_base(self._environ)
        cap = risk_streak_wait_max(self._environ)
        with self._lock:
            self.streak += 1
            streak = self.streak
            if streak >= stop_at:
                self.stopped = True
                self.pause_until = 0.0
                self.reason = f"连续{streak}次风控，已停止注册"
                return "stop", 0.0, streak
            if streak >= wait_start:
                level = streak - wait_start
                wait = min(float(cap), float(base) * (2 ** level))
                self.pause_until = ts + wait
                self.reason = f"连续{streak}次风控，暂停{int(wait)}s"
                return "wait", wait, streak
            self.pause_until = 0.0
            self.reason = f"连续{streak}次风控"
            return "ok", 0.0, streak

    def should_stop(self) -> bool:
        with self._lock:
            return bool(self.stopped)

    def remaining_wait(self, now: float | None = None) -> float:
        ts = time.time() if now is None else float(now)
        with self._lock:
            if self.stopped:
                return 0.0
            return max(0.0, float(self.pause_until) - ts)


BREAKER = RiskCircuitBreaker()


def reset_risk_breaker() -> None:
    BREAKER.reset()


def note_risk_success() -> None:
    BREAKER.note_success()


def note_risk_failure() -> tuple[str, float, int]:
    return BREAKER.note_risk()


def risk_breaker_should_stop() -> bool:
    return BREAKER.should_stop()


def apply_risk_breaker_wait(
    log: LogFn | None,
    should_stop: Callable[[], bool] | None,
    sleep_fn: Callable[[float, Callable[[], bool] | None], None],
) -> bool:
    """Pause or abort before the next account. True means stop the batch."""
    if BREAKER.should_stop():
        if log:
            log(f"[风控] {BREAKER.reason or '连续风控已熔断，停止注册'}")
        return True
    wait = BREAKER.remaining_wait()
    if wait > 0:
        if log:
            log(f"[风控] 连续风控暂停 {wait:.0f}s 后再试")
        sleep_fn(wait, should_stop)
    if BREAKER.should_stop():
        if log:
            log(f"[风控] {BREAKER.reason or '连续风控已熔断，停止注册'}")
        return True
    return False
