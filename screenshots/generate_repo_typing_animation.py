#!/usr/bin/env python3
"""Generate a GitHub-safe pseudo-3D typing animation for the README."""

from __future__ import annotations

import math
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT_GIF = ROOT / "repo-typing-analyst.gif"
FRAME_COUNT = 24
WIDTH = 460
HEIGHT = 360


def _screen_lines(frame_index: int) -> str:
    lines: list[str] = []
    offset = (frame_index * 7) % 18
    palette = ("#7ce8ff", "#54c7ff", "#f8b84a", "#35d1a3")
    for index in range(8):
        y = 82 + index * 16 + offset
        if y > 178:
            y -= 118
        width = 112 - ((index * 11 + frame_index * 5) % 42)
        color = palette[(index + frame_index) % len(palette)]
        opacity = 0.95 if index % 3 else 0.72
        lines.append(
            f'<rect x="193" y="{y}" width="{width}" height="6" rx="3" fill="{color}" opacity="{opacity:.2f}" />'
        )
    cursor_x = 193 + 46 + (frame_index % 5) * 10
    cursor_opacity = "1.0" if frame_index % 6 < 3 else "0.24"
    lines.append(
        f'<rect x="{cursor_x}" y="164" width="8" height="8" rx="2" fill="#ffffff" opacity="{cursor_opacity}" />'
    )
    return "\n      ".join(lines)


def build_frame(frame_index: int) -> str:
    t = frame_index / FRAME_COUNT
    primary_wave = math.sin(t * math.tau * 2)
    secondary_wave = math.cos(t * math.tau * 2)
    bounce = math.sin(t * math.tau) * 2.5
    hand_left_x = 258 + primary_wave * 5
    hand_left_y = 233 - secondary_wave * 4
    hand_right_x = 298 - primary_wave * 6
    hand_right_y = 230 + secondary_wave * 4
    elbow_left_x = 285 + primary_wave * 3
    elbow_left_y = 196 + secondary_wave * 2
    elbow_right_x = 323 - primary_wave * 3
    elbow_right_y = 192 - secondary_wave * 2
    shoulder_y = 152 + bounce
    head_y = 121 + bounce * 0.8
    monitor_glow = 0.78 + (secondary_wave + 1) * 0.08
    key_flash = 0.42 + (primary_wave + 1) * 0.18

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">
  <defs>
    <linearGradient id="panel" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0b1421" />
      <stop offset="100%" stop-color="#122033" />
    </linearGradient>
    <linearGradient id="deskTop" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1f3853" />
      <stop offset="100%" stop-color="#152636" />
    </linearGradient>
    <linearGradient id="monitorScreen" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#163247" />
      <stop offset="100%" stop-color="#0a1825" />
    </linearGradient>
    <linearGradient id="hoodie" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#233f61" />
      <stop offset="100%" stop-color="#16273b" />
    </linearGradient>
    <linearGradient id="skin" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f6c8a8" />
      <stop offset="100%" stop-color="#dda27a" />
    </linearGradient>
    <radialGradient id="screenGlow" cx="45%" cy="45%" r="60%">
      <stop offset="0%" stop-color="#2ce6ff" stop-opacity="{monitor_glow:.2f}" />
      <stop offset="100%" stop-color="#2ce6ff" stop-opacity="0" />
    </radialGradient>
    <radialGradient id="accentGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#35d1a3" stop-opacity="0.36" />
      <stop offset="100%" stop-color="#35d1a3" stop-opacity="0" />
    </radialGradient>
  </defs>

  <rect width="{WIDTH}" height="{HEIGHT}" rx="34" fill="url(#panel)" />
  <circle cx="95" cy="78" r="74" fill="url(#accentGlow)" />
  <circle cx="392" cy="78" r="56" fill="url(#accentGlow)" opacity="0.55" />
  <path d="M38 278 C126 244, 154 324, 244 286 S392 214, 426 266" fill="none" stroke="#35d1a3" stroke-opacity="0.14" stroke-width="2" />
  <path d="M52 296 C134 264, 198 336, 284 304 S390 252, 420 278" fill="none" stroke="#7ce8ff" stroke-opacity="0.10" stroke-width="2" />

  <ellipse cx="250" cy="284" rx="146" ry="26" fill="#040a12" opacity="0.40" />

  <polygon points="126,210 286,210 344,244 184,244" fill="url(#deskTop)" />
  <polygon points="286,210 344,244 344,263 286,230" fill="#10202d" />
  <polygon points="126,210 184,244 184,263 126,230" fill="#1b2c3d" />

  <polygon points="250,222 318,222 334,231 266,231" fill="#111d2a" />
  <polygon points="266,231 334,231 334,238 266,238" fill="#0b1621" />
  <g opacity="{key_flash:.2f}">
    <rect x="275" y="225" width="6" height="3" rx="1.5" fill="#7ce8ff" />
    <rect x="284" y="225" width="6" height="3" rx="1.5" fill="#35d1a3" />
    <rect x="293" y="225" width="6" height="3" rx="1.5" fill="#f8b84a" />
    <rect x="302" y="225" width="6" height="3" rx="1.5" fill="#7ce8ff" />
  </g>

  <polygon points="176,116 280,116 296,128 192,128" fill="#22384e" />
  <polygon points="192,128 296,128 296,196 192,196" fill="url(#monitorScreen)" />
  <polygon points="280,116 296,128 296,196 280,184" fill="#132332" />
  <rect x="186" y="121" width="104" height="78" rx="9" fill="url(#screenGlow)" />
  <g>
      {_screen_lines(frame_index)}
  </g>
  <rect x="227" y="197" width="32" height="9" rx="4.5" fill="#24384d" />
  <rect x="238" y="206" width="10" height="23" rx="4" fill="#162636" />

  <ellipse cx="340" cy="204" rx="40" ry="58" fill="#0d1621" opacity="0.28" />
  <rect x="344" y="190" width="10" height="56" rx="5" fill="#1f2f42" />
  <path d="M325 250 Q349 236 370 250" fill="none" stroke="#22384e" stroke-width="9" stroke-linecap="round" />

  <g transform="translate(0,{bounce:.2f})">
    <path d="M315 155 L343 155 L356 210 L304 210 Z" fill="url(#hoodie)" />
    <path d="M320 155 Q329 177 338 155" fill="none" stroke="#36597a" stroke-width="4" stroke-linecap="round" />
    <rect x="321" y="207" width="22" height="36" rx="8" fill="#1a2d42" />
    <rect x="332" y="160" width="7" height="22" rx="3.5" fill="#111d2a" />

    <path d="M326 {head_y + 7:.2f} q-6 -16 7 -26 q18 -12 34 -3 q15 8 15 25 v6 z" fill="#0d1621" />
    <circle cx="343" cy="{head_y:.2f}" r="19" fill="url(#skin)" />
    <path d="M326 {head_y + 4:.2f} q6 -22 28 -18 q13 2 20 12 q-5 -20 -24 -20 q-17 0 -24 12 z" fill="#0c1724" />
    <circle cx="336" cy="{head_y - 1.5:.2f}" r="2.1" fill="#122033" />
    <circle cx="349" cy="{head_y - 1.2:.2f}" r="2.1" fill="#122033" />
    <path d="M337 {head_y + 8:.2f} q6 5 13 0" fill="none" stroke="#a16545" stroke-width="2.4" stroke-linecap="round" />
    <path d="M324 {head_y + 1:.2f} q-5 4 -4 10" fill="none" stroke="#d4dbe6" stroke-width="5" stroke-linecap="round" />
    <path d="M362 {head_y + 1:.2f} q5 4 4 10" fill="none" stroke="#d4dbe6" stroke-width="5" stroke-linecap="round" />
    <path d="M324 {head_y + 1:.2f} q-5 4 -4 10" fill="none" stroke="#8898aa" stroke-width="2" stroke-linecap="round" />
    <path d="M362 {head_y + 1:.2f} q5 4 4 10" fill="none" stroke="#8898aa" stroke-width="2" stroke-linecap="round" />

    <path d="M320 {shoulder_y:.2f} L{elbow_left_x:.2f} {elbow_left_y:.2f} L{hand_left_x:.2f} {hand_left_y:.2f}" fill="none" stroke="#233f61" stroke-width="13" stroke-linecap="round" stroke-linejoin="round" />
    <path d="M320 {shoulder_y:.2f} L{elbow_left_x:.2f} {elbow_left_y:.2f} L{hand_left_x:.2f} {hand_left_y:.2f}" fill="none" stroke="#0f1b29" stroke-opacity="0.28" stroke-width="4" stroke-linecap="round" />
    <circle cx="{hand_left_x:.2f}" cy="{hand_left_y:.2f}" r="8.5" fill="url(#skin)" />

    <path d="M346 {shoulder_y + 1:.2f} L{elbow_right_x:.2f} {elbow_right_y:.2f} L{hand_right_x:.2f} {hand_right_y:.2f}" fill="none" stroke="#233f61" stroke-width="13" stroke-linecap="round" stroke-linejoin="round" />
    <path d="M346 {shoulder_y + 1:.2f} L{elbow_right_x:.2f} {elbow_right_y:.2f} L{hand_right_x:.2f} {hand_right_y:.2f}" fill="none" stroke="#0f1b29" stroke-opacity="0.28" stroke-width="4" stroke-linecap="round" />
    <circle cx="{hand_right_x:.2f}" cy="{hand_right_y:.2f}" r="8.5" fill="url(#skin)" />
  </g>

  <g opacity="0.95">
    <circle cx="74" cy="50" r="3.5" fill="#35d1a3" />
    <circle cx="88" cy="50" r="3.5" fill="#f8b84a" />
    <circle cx="102" cy="50" r="3.5" fill="#ff5d78" />
  </g>
</svg>
"""


def generate_animation() -> None:
    if shutil.which("convert") is None:
        raise RuntimeError("ImageMagick 'convert' is required to generate the README animation.")

    with tempfile.TemporaryDirectory(prefix="dips-typing-frames-") as tmp_dir:
        frame_dir = Path(tmp_dir)
        frame_paths: list[str] = []
        for frame_index in range(FRAME_COUNT):
            frame_path = frame_dir / f"frame-{frame_index:02d}.svg"
            frame_path.write_text(build_frame(frame_index), encoding="utf-8")
            frame_paths.append(str(frame_path))

        command = [
            "convert",
            "-background",
            "none",
            "-delay",
            "6",
            *frame_paths,
            "-loop",
            "0",
            "-layers",
            "Optimize",
            str(OUTPUT_GIF),
        ]
        subprocess.run(command, check=True)


if __name__ == "__main__":
    generate_animation()
