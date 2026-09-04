# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import account_ops


def test_detect_batch_is_concurrent():
    barrier = threading.Barrier(3, timeout=8)
    started = []

    def worker(email, log=None):
        started.append(email)
        barrier.wait()
        return {
            "risk_status": "clean",
            "risk_detail": "thinking",
            "detect": {"reason": "thinking", "flagged": False, "http_status": 200},
        }

    prev = os.environ.get("GROK_ACCOUNT_WORKERS")
    os.environ["GROK_ACCOUNT_WORKERS"] = "3"
    account_ops._set_job(
        running=True, kind="detect", total=3, done=0, ok=0, failed=0, error="", items=[]
    )
    try:
        t0 = time.monotonic()
        account_ops._run_batch("detect", ["a@x.com", "b@x.com", "c@x.com"], worker)
        elapsed = time.monotonic() - t0
    finally:
        if prev is None:
            os.environ.pop("GROK_ACCOUNT_WORKERS", None)
        else:
            os.environ["GROK_ACCOUNT_WORKERS"] = prev
    job = account_ops.job_status()
    assert job["ok"] == 3
    assert job["failed"] == 0
    assert job["workers"] == 3
    assert elapsed < 4
    assert len(started) == 3


def test_account_workers_cap():
    prev = os.environ.get("GROK_ACCOUNT_WORKERS")
    os.environ["GROK_ACCOUNT_WORKERS"] = "99"
    try:
        assert account_ops._account_workers("detect", 10) == account_ops.DETECT_WORKERS_MAX
        assert account_ops._account_workers("upload", 2) == 2
    finally:
        if prev is None:
            os.environ.pop("GROK_ACCOUNT_WORKERS", None)
        else:
            os.environ["GROK_ACCOUNT_WORKERS"] = prev


if __name__ == "__main__":
    test_detect_batch_is_concurrent()
    test_account_workers_cap()
    print("OK account ops")
