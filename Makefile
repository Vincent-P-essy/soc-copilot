.PHONY: install run test lint cov docker fmt

install:
	pip install -r requirements.txt

run:
	python -m backend.app

test:
	pytest

cov:
	pytest --cov=backend --cov-report=term-missing

lint:
	ruff check backend tests

fmt:
	ruff check --fix backend tests

docker:
	docker compose up --build
