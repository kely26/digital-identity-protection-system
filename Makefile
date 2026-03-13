.PHONY: clean test lint build release-check smoke dashboard

clean:
	rm -rf build dist *.egg-info

test:
	pytest

lint:
	ruff check .

build: clean
	python3 -m build

release-check: lint test build
	python3 -m twine check dist/*

smoke:
	python3 -m dips scan --path tests/fixtures/exposure --email-file tests/fixtures/email/phish.eml --password-file tests/fixtures/exposure/passwords.txt

dashboard:
	python3 -m dips.ui_dashboard
