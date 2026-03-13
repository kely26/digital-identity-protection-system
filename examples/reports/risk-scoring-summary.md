# Risk Scoring Summary

This summary is derived from `synthetic-incident-report.json` and is safe to share publicly.

## Overall Assessment

- Scan ID: `sample-identity-incident-001`
- Overall score: `86 / 100`
- Status: `HIGH`
- Risk model: `digital_identity_weighted_sum`
- Duration: `11240 ms`

## Severity Distribution

| Severity | Count |
| --- | ---: |
| Critical | 2 |
| High | 6 |
| Medium | 4 |
| Low | 1 |
| Info | 0 |

## Category Scores

| Category | Score |
| --- | ---: |
| Phishing risk | 44 |
| Token exposure | 35 |
| Breach exposure | 31 |
| Threat intelligence | 27 |
| Browser risk | 18 |
| Credential reuse | 12 |
| Password strength | 10 |
| Privacy risk | 8 |

## Primary Risk Drivers

- Threat-intelligence match for a malicious executive-review URL
- Plaintext GitHub token exposed in a synced notebook
- Finance identity appearing in staged breach collections
- Phishing message with Reply-To mismatch and failed email authentication
- Browser profile with disabled protection settings

## Recommended Actions

1. Revoke the exposed token and remove plaintext copies from local notes.
2. Reset the breached identity password and require MFA re-validation.
3. Block the malicious URL and domain in mail and web controls.
4. Re-enable browser protections and remove saved credentials from the affected profile.
5. Treat the phishing, breach, and secret-exposure findings as one correlated identity-security incident.
