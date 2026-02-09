.PHONY: validate test test-urls test-urls-offline precommit changelog release-notes pf-bootstrap

TAG ?=

validate:
	bash -n autosecure.sh tests/test_parsing.sh tests/test_urls.sh
	shellcheck autosecure.sh tests/test_parsing.sh tests/test_urls.sh
	bash tests/test_parsing.sh
	bash tests/test_urls.sh

test:
	bash tests/test_parsing.sh

test-urls:
	bash tests/test_urls.sh

test-urls-offline:
	AUTOSECURE_SKIP_NETWORK_TESTS=1 bash tests/test_urls.sh

precommit:
	pre-commit run --all-files

changelog:
	bash scripts/generate-changelog.sh > CHANGELOG.md

release-notes:
	@if [ -z "$(TAG)" ]; then echo "Usage: make release-notes TAG=vX.Y.Z"; exit 1; fi
	bash scripts/generate-release-notes.sh "$(TAG)"

pf-bootstrap:
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "pf-bootstrap is only supported on macOS."; \
		exit 1; \
	fi
	sudo touch /etc/pf.anchors/autosecure
	@sudo grep -q '^anchor "autosecure"$$' /etc/pf.conf || \
		echo 'anchor "autosecure"' | sudo tee -a /etc/pf.conf >/dev/null
	@sudo grep -q '^load anchor "autosecure" from "/etc/pf.anchors/autosecure"$$' /etc/pf.conf || \
		echo 'load anchor "autosecure" from "/etc/pf.anchors/autosecure"' | sudo tee -a /etc/pf.conf >/dev/null
	sudo pfctl -nf /etc/pf.conf
	sudo pfctl -f /etc/pf.conf
	sudo pfctl -e
	@echo "pf anchor configured and loaded."
