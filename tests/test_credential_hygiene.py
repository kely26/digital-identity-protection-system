from __future__ import annotations

from dips.scanners.credential_hygiene import CredentialHygieneScanner


def test_credential_hygiene_flags_reuse_and_common_passwords(default_config, make_context):
    context = make_context(
        config=default_config,
        password_inputs=["password", "password", "alice-Strong2024!", "Truly$Unique1"],
        user_identifiers=["alice"],
    )
    result = CredentialHygieneScanner().run(context)
    titles = {finding.title for finding in result.findings}

    assert result.status == "completed"
    assert "Password reuse detected" in titles
    assert "Common password detected" in titles
    assert "Short password detected" in titles
    assert "Password contains personal identifier" in titles
