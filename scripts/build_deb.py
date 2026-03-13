#!/usr/bin/env python3
"""Build a lightweight Debian package for DIPS."""

from __future__ import annotations

import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS_DIR = ROOT / "downloads"
VERSION_MATCH = re.search(
    r'__version__\s*=\s*"([^"]+)"',
    (ROOT / "dips" / "__init__.py").read_text(encoding="utf-8"),
)
if VERSION_MATCH is None:
    raise RuntimeError("Unable to determine DIPS version from dips/__init__.py")
VERSION = VERSION_MATCH.group(1)
WHEEL_NAME = f"digital_identity_protection_system-{VERSION}-py3-none-any.whl"
WHEEL_PATH = ROOT / "dist" / WHEEL_NAME
GUIDE_PATH = DOWNLOADS_DIR / f"DIPS_User_Guide_v{VERSION}.pdf"
DEB_PATH = DOWNLOADS_DIR / f"dips_{VERSION}_all.deb"


RUN_DIPS_SCRIPT = f"""#!/bin/sh
set -eu
ROOT=/opt/dips
RUNTIME="$ROOT/runtime"
WHEEL="$ROOT/artifacts/{WHEEL_NAME}"

ensure_runtime() {{
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to run DIPS." >&2
    exit 1
  fi
  if ! python3 - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
    echo "DIPS requires Python 3.11 or newer." >&2
    exit 1
  fi
  if [ ! -x "$RUNTIME/bin/python" ]; then
    mkdir -p "$ROOT"
    python3 -m venv "$RUNTIME"
    "$RUNTIME/bin/python" -m pip install --upgrade pip >/dev/null 2>&1 || true
    "$RUNTIME/bin/python" -m pip install --no-deps --upgrade "$WHEEL" >/dev/null
  fi
}}

ensure_runtime
exec "$RUNTIME/bin/python" -m dips.cli.main "$@"
"""


DASHBOARD_SCRIPT = """#!/bin/sh
set -eu
/opt/dips/bin/run-dips --version >/dev/null
if ! /opt/dips/runtime/bin/python - <<'PY' >/dev/null 2>&1
import PySide6
PY
then
  echo "Dashboard dependencies are not installed yet." >&2
  echo "Run: sudo dips-enable-gui" >&2
  exit 1
fi
exec /opt/dips/bin/run-dips dashboard "$@"
"""


ENABLE_GUI_SCRIPT = """#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "Run this command with sudo because /opt/dips/runtime is system-owned." >&2
  exit 1
fi
/opt/dips/bin/run-dips --version >/dev/null
/opt/dips/runtime/bin/python -m pip install --upgrade "PySide6>=6.8.0,<7"
echo "PySide6 installed. Launch the dashboard with: dips-dashboard"
"""


POSTINST_SCRIPT = """#!/bin/sh
set -eu
/opt/dips/bin/run-dips --version >/dev/null
echo "DIPS CLI runtime installed."
echo "Run 'dips doctor' to validate the environment."
echo "Run 'sudo dips-enable-gui' if you want the desktop dashboard."
"""


CONTROL_TEMPLATE = f"""Package: dips
Version: {VERSION}
Section: utils
Priority: optional
Architecture: all
Maintainer: Hackloi
Depends: python3 (>= 3.11), python3-venv
Homepage: https://github.com/kely26/digital-identity-protection-system
Description: Local-first digital identity protection system
 DIPS is a defensive local-first platform for identity exposure detection,
 breach intelligence, phishing analysis, browser posture review, and
 privacy-focused reporting.
 .
 This Debian package installs the CLI runtime and bundled guide.
 The dashboard can be enabled after install with the dips-enable-gui helper.
"""


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build_deb() -> Path:
    if not WHEEL_PATH.exists():
        raise FileNotFoundError(f"Wheel not found: {WHEEL_PATH}. Build the package first.")
    if not GUIDE_PATH.exists():
        raise FileNotFoundError(f"Guide not found: {GUIDE_PATH}. Generate the PDF first.")

    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="dips-deb-build-") as tmp_dir:
        tmp = Path(tmp_dir)
        pkg_root = tmp / "pkg"
        debian = pkg_root / "DEBIAN"
        opt_bin = pkg_root / "opt" / "dips" / "bin"
        opt_artifacts = pkg_root / "opt" / "dips" / "artifacts"
        opt_docs = pkg_root / "opt" / "dips" / "docs"
        usr_bin = pkg_root / "usr" / "bin"

        for path in (debian, opt_bin, opt_artifacts, opt_docs, usr_bin):
            path.mkdir(parents=True, exist_ok=True)

        (debian / "control").write_text(CONTROL_TEMPLATE, encoding="utf-8")
        _write_executable(debian / "postinst", POSTINST_SCRIPT)
        shutil.copy2(WHEEL_PATH, opt_artifacts / WHEEL_NAME)
        shutil.copy2(GUIDE_PATH, opt_docs / GUIDE_PATH.name)

        _write_executable(opt_bin / "run-dips", RUN_DIPS_SCRIPT)
        _write_executable(opt_bin / "dashboard", DASHBOARD_SCRIPT)
        _write_executable(opt_bin / "enable-gui", ENABLE_GUI_SCRIPT)

        _write_executable(usr_bin / "dips", '#!/bin/sh\nexec /opt/dips/bin/run-dips "$@"\n')
        _write_executable(usr_bin / "dips-doctor", '#!/bin/sh\nexec /opt/dips/bin/run-dips doctor "$@"\n')
        _write_executable(usr_bin / "dips-dashboard", '#!/bin/sh\nexec /opt/dips/bin/dashboard "$@"\n')
        _write_executable(usr_bin / "dips-enable-gui", '#!/bin/sh\nexec /opt/dips/bin/enable-gui "$@"\n')

        subprocess.run(
            ["dpkg-deb", "--build", "--root-owner-group", str(pkg_root), str(DEB_PATH)],
            check=True,
        )

    return DEB_PATH


if __name__ == "__main__":
    path = build_deb()
    print(path)
