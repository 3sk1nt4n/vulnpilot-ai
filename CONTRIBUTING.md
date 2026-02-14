# Contributing to VulnPilot AI

Thank you for your interest in VulnPilot AI.

## Important

VulnPilot AI is proprietary software owned by Solvent CyberSecurity LLC. External contributions are not accepted at this time.

If you have found a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md).

For feature requests, bug reports, or partnership inquiries, contact: info@solventcyber.com

## Internal Development

For Solvent CyberSecurity team members:

### Branch Naming

- `feature/description` for new features
- `fix/description` for bug fixes
- `hotfix/description` for urgent production fixes

### Commit Messages

Use conventional commits:

```
feat: add Azure asset collector
fix: resolve bcrypt crash on Python 3.12
docs: update README with cloud compliance section
test: add 22 cloud module unit tests
```

### Running Tests

```bash
cd backend
pytest tests/ -v
```

### Code Quality

```bash
ruff check backend/vulnpilot/ --select E,F,W --ignore E501
```

### Syntax Validation

```bash
find backend/ -name "*.py" -exec python -c "import ast; ast.parse(open('{}').read())" \;
```
