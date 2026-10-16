.PHONY: install test verify doctor clean api ui

VENV ?= .venv
PYTHON ?= $(VENV)/bin/python

install:
	uv venv --python /home/psw/.local/bin/python3.12 $(VENV)
	VIRTUAL_ENV=$(VENV) uv pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest tests/

doctor:
	$(PYTHON) -m auditforge.cli doctor

verify:
	bash scripts/verify.sh

api:
	$(PYTHON) -m uvicorn auditforge.api.app:app --reload --port 8000

ui:
	cd dashboard && npm run dev

clean:
	rm -rf .pytest_cache/ build/ dist/ *.egg-info .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
