# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please follow responsible disclosure:

1. **Do not open a public GitHub Issue.** Public disclosure before a fix is available can put users at risk.
2. Send a detailed report to: **security@hiagokinlevi.dev**
3. Include in your report:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested remediation (optional but appreciated)

## Response Timeline

- **Acknowledgment**: within 48 hours of receiving your report
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days for critical issues, 90 days for others
- **Public disclosure**: coordinated with the reporter after a fix is available

## Scope

This project is a read-only forensics toolkit. Vulnerabilities of particular interest include:

- Path traversal or arbitrary file read issues in parsers
- Command injection in collector subprocess calls
- Data leakage in JSONL output (e.g., credentials captured unintentionally)
- Dependencies with known CVEs

## Out of Scope

- Vulnerabilities in third-party dependencies (report upstream)
- Issues requiring physical access to the analyst's machine
- Social engineering attacks

## Recognition

Responsible disclosure reporters will be credited in the release notes (with their permission).

Thank you for helping keep this toolkit and its users safe.
