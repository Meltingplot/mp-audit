# The everyday commands, see CONTRIBUTING.md. The tools come from
# requirements-dev.txt into .venv; make venv is run for you when they are needed.

VENV ?= .venv
BIN := $(abspath $(VENV))/bin
UNIT := overlay/usr/lib/systemd/system/mp-audit.service

.DEFAULT_GOAL := help
.PHONY: help venv format lint unit test check clean

help: ## Show this list
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | expand -t 10

venv: $(BIN)/pre-commit ## Install the tools into .venv

$(BIN)/pre-commit: requirements-dev.txt
	python3 -m venv $(VENV)
	$(BIN)/pip install --quiet -r requirements-dev.txt
	touch $@

format: venv ## Format the Python
	$(BIN)/ruff format

lint: venv ## Style and lint, the hooks the CI runs
	PATH="$(BIN):$$PATH" $(BIN)/pre-commit run --all-files --show-diff-on-failure

unit: ## Check the systemd unit
	systemd-analyze verify --root=overlay --man=no $(UNIT)

test: venv ## The tests; T=test_chain runs only those named
	PATH="$(BIN):$$PATH" sh test/test-mp-audit.sh $(T)

check: lint unit test ## All of the above, as the CI does

clean: ## Remove the tools and the caches
	rm -rf $(VENV) .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
