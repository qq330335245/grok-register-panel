"""Registered-account registry (email/password/sso + risk/upload flags)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = Path(os.environ.get("GROK_ACCOUNTS_DIR", str(ROOT / "accounts")))
DB_PATH = Path(os.environ.get("GROK_ACCOUNT_DB", str(ACCOUNTS_DIR / "registry.sqlite")))

RISK_CLEAN = "clean"
RISK_FLAGGED = "flagged"
RISK_UNKNOWN = "unknown"
RISK_VALUES = (RISK_CLEAN, RISK_FLAGGED, RISK_UNKNOWN)
SORT_FIELDS = {
    "email": "email",
    "created_at": "created_at",
    "updated_at": "updated_at",
    "risk_status": "risk_status",
    "uploaded": "uploaded",
}

_LOCK = threading.RLock()
_INIT = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_email(value: object) -> str:
    return str(value or "").strip().lower()


def _connect() -> sqlite3.Connection:
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    global _INIT
    with _LOCK:
        if _INIT:
            return
        conn = _connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    email TEXT PRIMARY KEY,
                    password TEXT NOT NULL DEFAULT '',
                    sso TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    risk_status TEXT NOT NULL DEFAULT 'unknown',
                    risk_detail TEXT NOT NULL DEFAULT '',
                    risk_checked_at TEXT NOT NULL DEFAULT '',
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    uploaded_web INTEGER NOT NULL DEFAULT 0,
                    uploaded_build INTEGER NOT NULL DEFAULT 0,
                    uploaded_console INTEGER NOT NULL DEFAULT 0,
                    upload_skipped INTEGER NOT NULL DEFAULT 0,
                    token_exp INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_accounts_updated ON accounts(updated_at)"
            )
            conn.commit()
        finally:
            conn.close()
        _INIT = True


def upsert_account(
    email: str,
    *,
    password: str = "",
    sso: str = "",
    risk_status: str | None = None,
    risk_detail: str | None = None,
    risk_checked_at: str | None = None,
    uploaded: bool | None = None,
    uploaded_web: bool | None = None,
    uploaded_build: bool | None = None,
    uploaded_console: bool | None = None,
    upload_skipped: bool | None = None,
    token_exp: int | None = None,
) -> dict:
    init_db()
    addr = _norm_email(email)
    if not addr or "@" not in addr:
        raise ValueError("email required")
    now = _utc_now()
    status = str(risk_status or "").strip().lower()
    if status and status not in RISK_VALUES:
        status = RISK_UNKNOWN
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?", (addr,)
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO accounts (
                        email, password, sso, created_at, updated_at, risk_status,
                        risk_detail, risk_checked_at, uploaded, uploaded_web,
                        uploaded_build, uploaded_console, upload_skipped, token_exp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        addr,
                        str(password or ""),
                        str(sso or ""),
                        now,
                        now,
                        status or RISK_UNKNOWN,
                        str(risk_detail or ""),
                        str(risk_checked_at or ""),
                        1 if uploaded else 0,
                        1 if uploaded_web else 0,
                        1 if uploaded_build else 0,
                        1 if uploaded_console else 0,
                        1 if upload_skipped else 0,
                        int(token_exp or 0),
                    ),
                )
            else:
                password_v = str(password or "") or row["password"]
                sso_v = str(sso or "") or row["sso"]
                risk_v = status or row["risk_status"]
                detail_v = (
                    str(risk_detail) if risk_detail is not None else row["risk_detail"]
                )
                checked_v = (
                    str(risk_checked_at)
                    if risk_checked_at is not None
                    else row["risk_checked_at"]
                )
                up = row["uploaded"] if uploaded is None else (1 if uploaded else 0)
                up_web = (
                    row["uploaded_web"]
                    if uploaded_web is None
                    else (1 if uploaded_web else 0)
                )
                up_build = (
                    row["uploaded_build"]
                    if uploaded_build is None
                    else (1 if uploaded_build else 0)
                )
                up_con = (
                    row["uploaded_console"]
                    if uploaded_console is None
                    else (1 if uploaded_console else 0)
                )
                skipped = (
                    row["upload_skipped"]
                    if upload_skipped is None
                    else (1 if upload_skipped else 0)
                )
                exp_v = row["token_exp"] if token_exp is None else int(token_exp or 0)
                conn.execute(
                    """
                    UPDATE accounts SET
                        password=?, sso=?, updated_at=?, risk_status=?, risk_detail=?,
                        risk_checked_at=?, uploaded=?, uploaded_web=?, uploaded_build=?,
                        uploaded_console=?, upload_skipped=?, token_exp=?
                    WHERE email=?
                    """,
                    (
                        password_v,
                        sso_v,
                        now,
                        risk_v,
                        detail_v,
                        checked_v,
                        up,
                        up_web,
                        up_build,
                        up_con,
                        skipped,
                        exp_v,
                        addr,
                    ),
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?", (addr,)
            ).fetchone()
        finally:
            conn.close()
    return public_row(row)


def public_row(row: sqlite3.Row | None, *, secrets: bool = False) -> dict:
    if row is None:
        return {}
    data = {
        "email": row["email"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "risk_status": row["risk_status"],
        "risk_detail": row["risk_detail"],
        "risk_checked_at": row["risk_checked_at"],
        "uploaded": bool(row["uploaded"]),
        "uploaded_web": bool(row["uploaded_web"]),
        "uploaded_build": bool(row["uploaded_build"]),
        "uploaded_console": bool(row["uploaded_console"]),
        "upload_skipped": bool(row["upload_skipped"]),
        "token_exp": int(row["token_exp"] or 0),
        "token_expired": bool(
            int(row["token_exp"] or 0) and int(row["token_exp"] or 0) < int(datetime.now(timezone.utc).timestamp())
        ),
        "has_sso": bool(str(row["sso"] or "").strip()),
        "has_password": bool(str(row["password"] or "").strip()),
    }
    if secrets:
        data["password"] = str(row["password"] or "")
        data["sso"] = str(row["sso"] or "")
    return data


def get_account(email: str, *, secrets: bool = False) -> dict | None:
    init_db()
    addr = _norm_email(email)
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?", (addr,)
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return None
    return public_row(row, secrets=secrets)


def list_accounts(
    *,
    query: str = "",
    risk_status: str = "",
    uploaded: str = "",
    sort: str = "created_at",
    order: str = "desc",
    page: int = 1,
    page_size: int = 20,
) -> dict:
    init_db()
    maybe_import_files()
    clause: list[str] = []
    args: list[Any] = []
    q = str(query or "").strip().lower()
    if q:
        clause.append("email LIKE ?")
        args.append(f"%{q}%")
    risk = str(risk_status or "").strip().lower()
    if risk in RISK_VALUES:
        clause.append("risk_status = ?")
        args.append(risk)
    uploaded_f = str(uploaded or "").strip().lower()
    if uploaded_f in ("1", "true", "yes", "on"):
        clause.append("uploaded = 1")
    elif uploaded_f in ("0", "false", "no", "off"):
        clause.append("uploaded = 0")
    where = (" WHERE " + " AND ".join(clause)) if clause else ""
    sort_col = SORT_FIELDS.get(str(sort or "").strip(), "created_at")
    direction = "ASC" if str(order or "").strip().lower() == "asc" else "DESC"
    page = max(1, int(page or 1))
    page_size = max(1, min(500, int(page_size or 20)))
    offset = (page - 1) * page_size
    with _LOCK:
        conn = _connect()
        try:
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM accounts{where}", args
                ).fetchone()[0]
            )
            rows = conn.execute(
                f"SELECT * FROM accounts{where} ORDER BY {sort_col} {direction} LIMIT ? OFFSET ?",
                [*args, page_size, offset],
            ).fetchall()
            counts = {
                "total": total,
                "clean": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM accounts WHERE risk_status='clean'"
                    ).fetchone()[0]
                ),
                "flagged": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM accounts WHERE risk_status='flagged'"
                    ).fetchone()[0]
                ),
                "unknown": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM accounts WHERE risk_status='unknown'"
                    ).fetchone()[0]
                ),
                "uploaded": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM accounts WHERE uploaded=1"
                    ).fetchone()[0]
                ),
                "not_uploaded": int(
                    conn.execute(
                        "SELECT COUNT(*) FROM accounts WHERE uploaded=0"
                    ).fetchone()[0]
                ),
            }
        finally:
            conn.close()
    return {
        "ok": True,
        "items": [public_row(row) for row in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": max(1, (total + page_size - 1) // page_size) if total else 1,
        "counts": counts,
    }


def parse_account_line(text: str) -> tuple[str, str, str]:
    line = str(text or "").strip()
    if not line or line.startswith("#"):
        return "", "", ""
    parts = line.split("----")
    if len(parts) >= 3:
        return _norm_email(parts[0]), str(parts[1] or ""), str(parts[2] or "")
    if len(parts) == 2:
        left, right = parts
        if "@" in left:
            return _norm_email(left), "", str(right or "")
        return "", "", str(right or left)
    if "@" in line:
        return _norm_email(line), "", ""
    return "", "", line


def import_files(limit: int = 5000) -> int:
    init_db()
    if not ACCOUNTS_DIR.is_dir():
        return 0
    imported = 0
    for path in sorted(ACCOUNTS_DIR.glob("*.txt")):
        if imported >= limit:
            break
        name = path.name
        if name.startswith("accounts_") or name.startswith("sso_") or name in {
            "mail_credentials.txt",
        }:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        email, password, sso = parse_account_line(text.splitlines()[0] if text else "")
        if not email:
            stem = path.stem
            if "@" in stem:
                email = _norm_email(stem)
        if not email:
            continue
        upsert_account(email, password=password, sso=sso)
        imported += 1
    return imported


def delete_accounts(emails: list[str], *, remove_files: bool = True) -> dict:
    init_db()
    addrs = []
    seen = set()
    for raw in emails or []:
        email = _norm_email(raw)
        if email and email not in seen:
            seen.add(email)
            addrs.append(email)
    deleted = 0
    missing = 0
    with _LOCK:
        conn = _connect()
        try:
            for email in addrs:
                cur = conn.execute("DELETE FROM accounts WHERE email = ?", (email,))
                if cur.rowcount:
                    deleted += 1
                    if remove_files:
                        path = ACCOUNTS_DIR / f"{email}.txt"
                        try:
                            path.unlink(missing_ok=True)
                        except OSError:
                            pass
                else:
                    missing += 1
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "deleted": deleted, "missing": missing, "requested": len(addrs)}


def maybe_import_files() -> None:
    init_db()
    with _LOCK:
        conn = _connect()
        try:
            n = int(conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])
        finally:
            conn.close()
    if n == 0:
        import_files()
