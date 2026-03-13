from __future__ import annotations

from dips.scanners.privacy_risk import PrivacyRiskScanner


def test_privacy_risk_flags_history_and_permissions(default_config, make_context, tmp_path):
    profile = tmp_path / "home"
    (profile / ".ssh").mkdir(parents=True)
    (profile / ".aws").mkdir(parents=True)
    (profile / ".bash_history").write_text("export TOKEN=abc\n", encoding="utf-8")
    ssh_key = profile / ".ssh" / "id_rsa"
    ssh_key.write_text("PRIVATE KEY", encoding="utf-8")
    ssh_key.chmod(0o644)
    (profile / ".aws" / "credentials").write_text("[default]\naws_access_key_id=AKIA...\n", encoding="utf-8")

    context = make_context(config=default_config, user_profile=profile, target_paths=[profile], platform_name="linux")
    result = PrivacyRiskScanner().run(context)
    titles = {finding.title for finding in result.findings}

    assert "Shell history file present" in titles
    assert "Private SSH key stored in profile" in titles
    assert "Sensitive file has broad permissions" in titles
    assert "Sensitive credential store detected" in titles


def test_privacy_risk_windows_export_detection(default_config, make_context, tmp_path):
    profile = tmp_path / "windows-home"
    downloads = profile / "Downloads"
    downloads.mkdir(parents=True)
    (downloads / "browser_password_export.csv").write_text("site,username,password\n", encoding="utf-8")

    context = make_context(config=default_config, user_profile=profile, target_paths=[profile], platform_name="windows")
    result = PrivacyRiskScanner().run(context)

    assert any(finding.title == "Possible browser or credential export detected" for finding in result.findings)
