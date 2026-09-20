# -*- coding: utf-8 -*-
"""Camoufox 启动指纹约束：屏幕、WebGL、humanize、Xvfb。

和 create_browser_options 共用，避免把 UA 贴纸当多样性。
Xvfb 必须大于最大指纹屏，否则窗口会被虚拟屏卡住。
"""
from __future__ import annotations

import os
import random
import sqlite3
from typing import Optional, Sequence, Tuple

# 常见 Windows 桌面分辨率。最大 2560x1440，Xvfb 默认 3840x2160。
COMMON_WIN_SCREENS: Sequence[Tuple[int, int]] = (
    (1366, 768),
    (1440, 900),
    (1536, 864),
    (1600, 900),
    (1920, 1080),
    (1920, 1200),
    (2560, 1440),
)
XVFB_SCREEN_SPEC = "3840x2160x24"
HUMANIZE_MIN_S = 0.7
HUMANIZE_MAX_S = 1.8
SOFTWARE_WEBGL_MARKERS = (
    "swiftshader",
    "llvmpipe",
    "softpipe",
    "basic render driver",
    "microsoft basic render",
    "subzero",
)
_WEBGL_OS_SQL = {
    "windows": "win",
    "macos": "mac",
    "linux": "lin",
    "win": "win",
    "mac": "mac",
    "lin": "lin",
}


def xvfb_screen_spec(*, environ: Optional[dict] = None) -> str:
    env = os.environ if environ is None else environ
    raw = str(env.get("GROK_XVFB_SCREEN", "") or "").strip()
    return raw or XVFB_SCREEN_SPEC


def xvfb_screen_arg(*, environ: Optional[dict] = None) -> str:
    return f"-screen 0 {xvfb_screen_spec(environ=environ)}"


def pick_fingerprint_screen(rng: Optional[random.Random] = None) -> Tuple[int, int]:
    picker = rng.choice if rng is not None else random.choice
    return picker(list(COMMON_WIN_SCREENS))


def pick_humanize_seconds(rng: Optional[random.Random] = None) -> float:
    sample = rng.uniform if rng is not None else random.uniform
    return round(float(sample(HUMANIZE_MIN_S, HUMANIZE_MAX_S)), 2)


def is_software_webgl(renderer: str, vendor: str = "") -> bool:
    blob = f"{vendor} {renderer}".lower()
    return any(marker in blob for marker in SOFTWARE_WEBGL_MARKERS)


def _webgl_db_path() -> Optional[str]:
    try:
        from camoufox.webgl.sample import DB_PATH
    except Exception:
        return None
    path = str(DB_PATH)
    return path if os.path.isfile(path) else None


def pick_webgl_config(
    os_name: str = "windows",
    rng: Optional[random.Random] = None,
) -> Optional[Tuple[str, str]]:
    """从 Camoufox WebGL 库抽一对桌面卡，排除 WARP / SwiftShader。"""
    sql_os = _WEBGL_OS_SQL.get(str(os_name or "windows").strip().lower())
    if not sql_os:
        return None
    db_path = _webgl_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                f"SELECT vendor, renderer FROM webgl_fingerprints WHERE {sql_os} > 0"
            ).fetchall()
        finally:
            conn.close()
    except Exception:
        return None
    usable = [
        (str(vendor), str(renderer))
        for vendor, renderer in rows
        if vendor and renderer and not is_software_webgl(str(renderer), str(vendor))
    ]
    if not usable:
        return None
    picker = rng.choice if rng is not None else random.choice
    return picker(usable)


def try_screen_constraint(width: int, height: int):
    """BrowserForge Screen；库不在时返回 None。"""
    try:
        from browserforge.fingerprints import Screen
    except Exception:
        return None
    try:
        return Screen(
            min_width=int(width),
            max_width=int(width),
            min_height=int(height),
            max_height=int(height),
        )
    except Exception:
        return None
