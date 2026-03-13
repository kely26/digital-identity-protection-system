from __future__ import annotations

import json

from dips.core.config import load_config
from dips.core.context import build_scan_context


def test_build_scan_context_discovers_candidate_files(tmp_path, default_config, monkeypatch):
    profile = tmp_path / "home"
    docs = profile / "Documents"
    docs.mkdir(parents=True)
    (docs / "notes.txt").write_text("email=sam@example.com\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    default_config.scan.paths = [str(docs)]
    context = build_scan_context(default_config)

    assert context.target_paths == [docs.resolve()]
    assert len(context.candidate_files) == 1
    assert "Discovered 1 candidate files in scan scope." in context.notes


def test_build_scan_context_accepts_windows_style_scan_path(tmp_path, default_config, monkeypatch):
    profile = tmp_path / "profile"
    docs = profile / "Documents"
    docs.mkdir(parents=True)
    (docs / "windows-notes.txt").write_text("token=abc123\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    default_config.scan.paths = [r"%USERPROFILE%\Documents"]
    context = build_scan_context(default_config)

    assert context.target_paths == [docs.resolve()]
    assert {path.name for path in context.candidate_files} == {"windows-notes.txt"}


def test_build_scan_context_skips_unreadable_input_paths(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    password_dir = tmp_path / "password-dir"
    password_dir.mkdir()
    email_dir = tmp_path / "email-dir"
    email_dir.mkdir()
    override = tmp_path / "override.json"
    override.write_text(
        json.dumps(
            {
                "credential": {"password_file": str(password_dir)},
                "email": {"inputs": [str(email_dir)]},
            }
        ),
        encoding="utf-8",
    )

    context = build_scan_context(load_config(str(override)))

    assert context.password_inputs == []
    assert context.email_inputs == []
    assert any("Password file path is not a regular file" in note for note in context.notes)
    assert any("Email input is not a regular file" in note for note in context.notes)
