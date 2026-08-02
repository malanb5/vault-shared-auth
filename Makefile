.PHONY: setup test

setup:
	uv sync --extra dev

test: setup
	uv run pytest
