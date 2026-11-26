# Contributing to E-TAP

## Running the tests

Run these before you open a pull request.

**Backend** (Python 3.11). The tests need `tesseract-ocr` and `libzbar0` installed on your system.

    pip install -r backend/requirements.txt -r backend/requirements-dev.txt
    cd backend
    USE_FAKE_DB=1 python -m pytest tests -q --ignore=tests/test_threat_intel_live.py

**Frontend** (Node 22):

    cd frontend
    npm ci
    npm test
    npx vite build

If you change a user-facing feature, update `README.md` and `CONTEXT.md` in the same pull request.

**Extension** (Node 24), from the repository root:

    node --test --test-isolation=none extension/tests/*.test.mjs

## Proposing a change

1. Fork the project and create a branch from `main`.
2. Make a small, focused change and add or update tests for it.
3. Run the tests above for the parts you touched.
4. Open a pull request that says what changed and why.

Changes to the behaviour rules in `backend/sandbox/rules/` also have their own tests:

    cd backend
    python -m pytest tests/test_sandbox_rules.py -q

## Licence

By contributing, you agree that your contributions are released under the MIT licence in `LICENSE`.
