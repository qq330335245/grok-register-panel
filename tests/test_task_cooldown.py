# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from task_cooldown import (
    apply_task_cooldown_wait,
    note_task_success,
    remaining_task_cooldown,
    reset_task_cooldown,
)


def test_every_n_triggers_wait(tmp_path=None):
    with tempfile.TemporaryDirectory() as temp:
        env = {
            "GROK_TASK_COOLDOWN_EVERY": "3",
            "GROK_TASK_COOLDOWN_SECONDS": "45",
            "GROK_TASK_COOLDOWN_FILE": str(Path(temp) / "cool.json"),
        }
        reset_task_cooldown(env)
        assert note_task_success(now=10, environ=env) == (1, 0.0)
        assert note_task_success(now=11, environ=env) == (2, 0.0)
        ok, wait = note_task_success(now=12, environ=env)
        assert ok == 3 and wait == 45
        ok, remain = remaining_task_cooldown(now=12, environ=env)
        assert ok == 3 and remain == 45
        ok, remain = remaining_task_cooldown(now=57, environ=env)
        assert remain == 0
        ok, wait = note_task_success(now=58, environ=env)
        assert ok == 4 and wait == 0.0
        ok, wait = note_task_success(now=59, environ=env)
        assert wait == 0.0
        ok, wait = note_task_success(now=60, environ=env)
        assert ok == 6 and wait == 45


def test_zero_every_disables():
    with tempfile.TemporaryDirectory() as temp:
        env = {
            "GROK_TASK_COOLDOWN_EVERY": "0",
            "GROK_TASK_COOLDOWN_SECONDS": "99",
            "GROK_TASK_COOLDOWN_FILE": str(Path(temp) / "cool.json"),
        }
        reset_task_cooldown(env)
        for i in range(5):
            ok, wait = note_task_success(now=i, environ=env)
            assert wait == 0.0
        assert ok == 5


def test_apply_wait_sleeps_then_continues():
    slept = []
    with tempfile.TemporaryDirectory() as temp:
        env = {
            "GROK_TASK_COOLDOWN_EVERY": "1",
            "GROK_TASK_COOLDOWN_SECONDS": "8",
            "GROK_TASK_COOLDOWN_FILE": str(Path(temp) / "cool.json"),
        }
        reset_task_cooldown(env)
        note_task_success(environ=env)
        stop = apply_task_cooldown_wait(
            None,
            lambda: False,
            lambda seconds, _stop: slept.append(seconds),
            environ=env,
        )
        assert stop is False
        assert slept and slept[0] > 0


if __name__ == "__main__":
    test_every_n_triggers_wait()
    test_zero_every_disables()
    test_apply_wait_sleeps_then_continues()
    print("OK task cooldown")
