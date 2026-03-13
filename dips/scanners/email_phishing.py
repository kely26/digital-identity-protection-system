"""Email and phishing analysis."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

from dips.core.models import ModuleResult
from dips.modules.base import ScannerModule
from dips.utils.patterns import RISKY_ATTACHMENT_RE, SUSPICIOUS_URL_RE, URGENT_WORDS_RE, URL_RE
from dips.utils.secure_io import read_bytes_limited


class EmailPhishingScanner(ScannerModule):
    name = "email_phishing"
    description = "Analyzes email headers, links, and attachments for phishing indicators."

    def _load_message(self, path: Path):
        if path.suffix.lower() == ".eml":
            return BytesParser(policy=policy.default).parsebytes(read_bytes_limited(path, max_bytes=5 * 1024 * 1024))
        return Parser(policy=policy.default).parsestr(path.read_text(encoding="utf-8", errors="replace"))

    def _body_text(self, message) -> str:
        if message.is_multipart():
            parts = []
            for part in message.walk():
                if part.get_content_disposition() == "attachment":
                    continue
                if part.get_content_type() == "text/plain":
                    try:
                        parts.append(part.get_content())
                    except LookupError:
                        continue
            return "\n".join(parts)
        try:
            return message.get_content()
        except LookupError:
            return ""

    def run(self, context) -> ModuleResult:
        if not context.email_inputs:
            return self.skipped("No email files were provided; supply --email-file or email.inputs.")

        findings = []
        warnings: list[str] = []
        processed = 0
        for email_path in context.email_inputs:
            try:
                message = self._load_message(email_path)
            except (OSError, ValueError) as exc:
                warnings.append(f"Email input could not be read and was skipped: {email_path} ({exc})")
                continue
            processed += 1
            location = str(email_path)
            from_name, from_email = parseaddr(message.get("From", ""))
            _, reply_to_email = parseaddr(message.get("Reply-To", ""))
            subject = message.get("Subject", "")
            auth_results = message.get("Authentication-Results", "")
            received_spf = message.get("Received-SPF", "")
            body = self._body_text(message)
            urls = URL_RE.findall(body)

            if from_email and reply_to_email and from_email.lower() != reply_to_email.lower():
                findings.append(
                    self.build_finding(
                        severity="high",
                        confidence="high",
                        title="From and Reply-To addresses do not match",
                        summary="The sender address and reply target differ, which is a common phishing indicator.",
                        evidence={"from": from_email, "reply_to": reply_to_email, "subject": subject},
                        location=location,
                        recommendation="Verify the sender independently before replying or following instructions.",
                        tags=["email", "reply-to", "phishing"],
                    )
                )

            auth_text = f"{auth_results} {received_spf}".lower()
            if any(token in auth_text for token in ("spf=fail", "spf=softfail", "dkim=fail", "dmarc=fail", "fail")):
                findings.append(
                    self.build_finding(
                        severity="high",
                        confidence="medium",
                        title="Email authentication failure indicated",
                        summary="SPF, DKIM, or DMARC failure indicators were present in email headers.",
                        evidence={"authentication_results": auth_results, "received_spf": received_spf},
                        location=location,
                        recommendation="Treat the message as suspicious until the sender is confirmed through another channel.",
                        tags=["email", "authentication", "phishing"],
                    )
                )

            suspicious_urls = []
            for url in urls:
                host = urlparse(url).hostname or ""
                if "xn--" in host or SUSPICIOUS_URL_RE.search(url):
                    suspicious_urls.append(url)
            if suspicious_urls:
                findings.append(
                    self.build_finding(
                        severity="high",
                        confidence="high",
                        title="Suspicious URLs detected in email body",
                        summary="The email body contains punycode or IP-literal URLs commonly used in phishing campaigns.",
                        evidence={"urls": suspicious_urls[:5], "subject": subject},
                        location=location,
                        recommendation="Avoid clicking links directly; inspect domains carefully and verify sender legitimacy first.",
                        tags=["email", "url", "phishing"],
                    )
                )

            if URGENT_WORDS_RE.search(f"{subject}\n{body}"):
                findings.append(
                    self.build_finding(
                        severity="medium",
                        confidence="medium",
                        title="Urgency or pressure language detected",
                        summary="The email contains pressure-oriented language associated with phishing lures.",
                        evidence={"subject": subject, "from_name": from_name},
                        location=location,
                        recommendation="Slow down and validate unexpected requests that rely on urgency or fear.",
                        tags=["email", "social-engineering"],
                    )
                )

            risky_attachments = []
            for part in message.walk():
                if part.get_content_disposition() != "attachment":
                    continue
                filename = part.get_filename() or ""
                if filename and RISKY_ATTACHMENT_RE.search(filename):
                    risky_attachments.append(filename)
            if risky_attachments:
                findings.append(
                    self.build_finding(
                        severity="high",
                        confidence="high",
                        title="Risky email attachment type detected",
                        summary="The email contains an attachment type frequently used in phishing or malware delivery.",
                        evidence={"attachments": risky_attachments},
                        location=location,
                        recommendation="Do not open unexpected executables or script attachments from email.",
                        tags=["email", "attachment", "malware"],
                    )
                )

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            warnings=warnings,
            metadata={"emails_scanned": len(context.email_inputs), "emails_processed": processed},
        )
