# Contributing to mcp-ward

Thank you for helping strengthen security tooling for MCP servers and agent skills.

## Development Setup

```bash
git clone https://github.com/forgemorrow/mcp-ward.git
cd mcp-ward
pip install -e ".[dev]"
```

## Running Checks

Before opening a pull request, verify compilation, unit tests, and self-checks:

```bash
python -m compileall -q src tests examples
pytest tests/ -v
PYTHONPATH=src python -m mcp_ward scan examples/clean_workspace --fail-on LOW
PYTHONPATH=src python -m mcp_ward eval
```

## Pull Request Guidelines

- Keep runtime dependencies zero-install (`dependencies = []` in `pyproject.toml`) so `mcp-ward` stays portable in CI and air-gapped environments.
- Include targeted regression tests under `tests/` for every new detection rule, guardrail policy, or proxy behavior.
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`).
