# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in VulnPilot AI, please report it responsibly.

**Do NOT open a public issue.** Instead, email: security@solventcyber.com

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- Acknowledgment within 24 hours
- Initial assessment within 72 hours
- Fix timeline communicated within 1 week

## Scope

The following are in scope:

- VulnPilot AI backend (FastAPI, Python)
- Authentication and authorization bypass
- API endpoint security
- Input validation and injection attacks
- Guardrail bypass (jailbreak, prompt injection)
- Credential exposure in logs or responses
- Docker configuration weaknesses

The following are out of scope:

- Third-party dependencies (report to their maintainers)
- Social engineering attacks
- Denial of service (unless trivially exploitable)

## Security Features

VulnPilot AI includes multiple security layers:

- 4-layer guardrails (input, output, escalation, RAG defense)
- JWT authentication with role-based access control
- No credentials in logs or API responses
- bcrypt password hashing
- CORS configuration
- Rate limiting on external API calls

## Contact

- Email: security@solventcyber.com
- Company: Solvent CyberSecurity LLC
- Website: https://solventcyber.com
