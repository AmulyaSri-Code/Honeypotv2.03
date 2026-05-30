.PHONY: deploy local status logs stop test quick-test

deploy:
	./scripts/quick_deploy.sh docker

local:
	./scripts/quick_deploy.sh local

status:
	docker compose ps

logs:
	docker compose logs -f honeypot

stop:
	docker compose down

test:
	.venv/bin/python -m pytest -q

quick-test:
	.venv/bin/python -m pytest tests/test_setup_config.py tests/test_security_hardening.py -q
