# Contributing to Aegis

## Development setup

```bash
git clone <repository-url>
cd Aegis
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Running tests

```bash
pytest
```

Run a specific test file:

```bash
pytest tests/test_auth.py
```

## Code quality

- Follow existing code style (frozen dataclasses for models, type hints,
  no wildcard imports, no `except: pass` without justification)
- All functions should have type annotations
- Use descriptive variable names
- Keep functions focused and small

## Security-sensitive code

Code in the following areas requires extra scrutiny and must be reviewed
by at least one other contributor before merging:

- Authentication (`auth.py`)
- Authorization (`rbac.py`)
- Policy engine (`engine.py`)
- Gateway (`gateway.py`)
- Audit log (`audit.py`)
- Any code that executes processes, makes network requests, or reads files
- API authentication and token handling
- Any change that affects the fail-closed property

## Pull request expectations

- Every PR should address a single concern
- Include a clear summary of what the PR does and why
- Reference any related issues
- Add or update tests for behavior changes
- Run the full test suite before submitting
- Verify that `pip install -e .` still works

## Commit expectations

- Write clear, concise commit messages
- Use present tense ("Add feature" not "Added feature")
- Keep commits focused on a single logical change
- Do not include secrets, credentials, or personal data in commits
- Do not commit generated files, compiled artifacts, or local configuration

## No secrets or personal data

Before committing, verify that your changes do not include:

- Hardcoded passwords or API keys
- Session tokens or authentication secrets
- Personal information (email addresses, phone numbers, real names)
- Local absolute paths specific to your machine
- Configuration files containing secrets

If you discover a secret that has been committed, rotate it immediately
and contact the maintainers.

## Adding tests

Behavior changes must include corresponding tests. Tests should:

- Cover the new behavior
- Verify the fail-closed and default-deny properties when applicable
- Not depend on network connectivity unless unavoidable
- Clean up after themselves when using local storage
