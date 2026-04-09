# Contributing to k1n DFIR Attack Lab

Thank you for your interest in contributing. This project exists to help the security community perform effective, ethical, and reproducible incident response.

---

## Core Principle

**All contributions must maintain the read-only, non-destructive philosophy of this toolkit.**

No code that writes to, modifies, or deletes files on a target system will be accepted. Every collector must be provably non-destructive and every parser must operate on copies of log artifacts, not live system state.

---

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/dfir-attack-lab.git
   cd dfir-attack-lab
   ```
3. Install in development mode:
   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install -e ".[dev]"
   ```
4. Verify the test suite passes:
   ```bash
   pytest
   ```

---

## How to Contribute

### Bug Reports

Open a GitHub Issue with:
- A clear description of the bug
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS

### New Parsers

If you want to add a parser for a new log source (e.g., Windows Event Log, macOS Unified Log, syslog):

1. Create `parsers/<source_name>.py`
2. Return a `list[TriageEvent]` using the normalized model in `normalizers/models.py`
3. Add tests in `tests/test_<source_name>_parser.py` with at least three test cases
4. Update `ROADMAP.md` to mark the feature as implemented

### New Collectors

If you want to add a collector for a new platform:

1. Create `collectors/<platform>/triage.py`
2. Follow the pattern in `collectors/linux/triage.py`: use `_run_safe` or equivalent, never write to target
3. Add tests and update the README

### Pull Requests

- Keep PRs focused on a single change
- Write clear commit messages (imperative mood: "Add Windows Event Log parser")
- All tests must pass and coverage must remain above 70%
- Include inline comments on all non-trivial logic

---

## Code Style

- Python 3.11+
- Type hints on all public functions
- Docstrings on all public modules, classes, and functions
- No external dependencies beyond those declared in `pyproject.toml`

---

## Questions

Open a GitHub Discussion or contact security@hiagokinlevi.dev.
