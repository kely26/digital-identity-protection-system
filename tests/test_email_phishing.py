from __future__ import annotations

from pathlib import Path

from dips.scanners.email_phishing import EmailPhishingScanner


def test_email_phishing_detects_multiple_indicators(default_config, make_context):
    email_fixture = Path(__file__).parent / "fixtures" / "email" / "phish.eml"
    context = make_context(config=default_config, email_inputs=[email_fixture])
    result = EmailPhishingScanner().run(context)
    titles = {finding.title for finding in result.findings}

    assert "From and Reply-To addresses do not match" in titles
    assert "Email authentication failure indicated" in titles
    assert "Suspicious URLs detected in email body" in titles
    assert "Urgency or pressure language detected" in titles
    assert "Risky email attachment type detected" in titles


def test_email_phishing_skips_unreadable_inputs(default_config, make_context, tmp_path):
    unreadable = tmp_path / "maildir"
    unreadable.mkdir()
    context = make_context(config=default_config, email_inputs=[unreadable])

    result = EmailPhishingScanner().run(context)

    assert result.status == "completed"
    assert result.findings == []
    assert any("could not be read and was skipped" in warning for warning in result.warnings)


def test_email_phishing_skips_oversized_eml(default_config, make_context, tmp_path):
    huge_email = tmp_path / "huge.eml"
    huge_email.write_bytes(b"Subject: test\n\n" + (b"A" * (5 * 1024 * 1024 + 16)))
    context = make_context(config=default_config, email_inputs=[huge_email])

    result = EmailPhishingScanner().run(context)

    assert result.findings == []
    assert any("maximum supported size" in warning for warning in result.warnings)
