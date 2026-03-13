.PHONY: clean test lint build release-check smoke dashboard doctor guide-pdf deb-package downloads

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

doctor:
	python3 -m dips doctor

guide-pdf:
	./.venv/bin/python scripts/build_user_guide_pdf.py

deb-package:
	./.venv/bin/python scripts/build_deb.py

downloads: guide-pdf deb-package
	sha256sum downloads/DIPS_User_Guide_v0.1.1.pdf downloads/dips_0.1.1_all.deb > downloads/SHA256SUMS.txt
