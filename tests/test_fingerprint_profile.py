# -*- coding: utf-8 -*-
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fingerprint_profile import (  # noqa: E402
    COMMON_WIN_SCREENS,
    XVFB_SCREEN_SPEC,
    is_software_webgl,
    pick_fingerprint_screen,
    pick_humanize_seconds,
    pick_webgl_config,
    xvfb_screen_arg,
    xvfb_screen_spec,
)
from runtime_platform import batch_launch_command  # noqa: E402


def test_xvfb_default_fits_largest_win_screen():
    assert XVFB_SCREEN_SPEC == "3840x2160x24"
    max_w = max(w for w, _h in COMMON_WIN_SCREENS)
    max_h = max(h for _w, h in COMMON_WIN_SCREENS)
    spec_w, spec_h, _ = XVFB_SCREEN_SPEC.split("x")
    assert int(spec_w) >= max_w
    assert int(spec_h) >= max_h
    assert xvfb_screen_arg() == "-screen 0 3840x2160x24"


def test_xvfb_screen_env_override():
    env = {"GROK_XVFB_SCREEN": "2560x1440x24"}
    assert xvfb_screen_spec(environ=env) == "2560x1440x24"
    assert xvfb_screen_arg(environ=env) == "-screen 0 2560x1440x24"


def test_pick_fingerprint_screen_is_common_win():
    rng = random.Random(0)
    seen = {pick_fingerprint_screen(rng) for _ in range(40)}
    assert seen <= set(COMMON_WIN_SCREENS)
    assert len(seen) >= 3


def test_pick_humanize_seconds_range():
    rng = random.Random(1)
    samples = [pick_humanize_seconds(rng) for _ in range(20)]
    assert all(0.7 <= s <= 1.8 for s in samples)
    assert len(set(samples)) >= 5


def test_software_webgl_markers():
    assert is_software_webgl(
        "ANGLE (Microsoft, Microsoft Basic Render Driver Direct3D11 vs_5_0 ps_5_0)"
    )
    assert is_software_webgl(
        "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)))"
    )
    assert not is_software_webgl(
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar"
    )


def test_pick_webgl_config_skips_software_when_db_present():
    cfg = pick_webgl_config("windows", rng=random.Random(2))
    if cfg is None:
        return
    vendor, renderer = cfg
    assert vendor and renderer
    assert not is_software_webgl(renderer, vendor)


def test_batch_launch_uses_large_xvfb():
    import tempfile

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / ".venv" / "bin").mkdir(parents=True)
        python = root / ".venv" / "bin" / "python"
        python.write_text("")
        python.chmod(0o755)
        command = batch_launch_command(
            root,
            1,
            1,
            platform_name="linux",
            environ={},
            which=lambda name: "/usr/bin/xvfb-run" if name == "xvfb-run" else None,
        )
        assert command[:4] == [
            "/usr/bin/xvfb-run",
            "-a",
            "-s",
            "-screen 0 3840x2160x24",
        ]


if __name__ == "__main__":
    test_xvfb_default_fits_largest_win_screen()
    test_xvfb_screen_env_override()
    test_pick_fingerprint_screen_is_common_win()
    test_pick_humanize_seconds_range()
    test_software_webgl_markers()
    test_pick_webgl_config_skips_software_when_db_present()
    test_batch_launch_uses_large_xvfb()
    print("OK fingerprint profile")
