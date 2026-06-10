.PHONY: setup up down test test-integration test-all seed snapshot history help logs reset \
        demo-authorized demo-tamper demo-replay \
        demo-overscope demo-expired demo-fake \
        demo-injection demo-schema demo-ratelimit \
        demo-mmr-tamper demo-calendar demo-gmail \
        demo-mcp demo-full

help:
	@echo "LICITRA Execution Gateway — available targets:"
	@echo ""
	@echo "  make up          — start all containers"
	@echo "  make down        — stop all containers"
	@echo "  make seed        — populate with demo data"
	@echo "  make test        — run 54 unit tests"
	@echo "  make test-integration — run 37 integration tests"
	@echo "  make test-all    — run all 91 tests"
	@echo "  make demo-full   — run all 10 attack demos"
	@echo "  make logs        — tail API logs"
	@echo "  make snapshot    — save metrics snapshot"
	@echo "  make reset       — full reset (down -v + up + seed)"
	@echo ""

setup:
	cp -n .env.example .env || true

up:
	docker compose up --build -d

down:
	docker compose down

test:
	docker compose exec api pytest tests/unit/ -v

test-integration:
	docker compose exec api pytest tests/integration/ -v

test-all:
	docker compose exec api pytest tests/ -v --tb=short

seed:
	docker compose exec api python scripts/seed.py

snapshot:
	docker compose exec api python -c "import httpx; r=httpx.post('http://localhost:8000/metrics/snapshot'); print(r.json())"

history:
	docker compose exec api python -c "import httpx; r=httpx.get('http://localhost:8000/metrics/history'); [print(s) for s in r.json()]"

demo-authorized:
	docker compose exec api python apps/demo-agent/authorized_action.py

demo-tamper:
	docker compose exec api python apps/demo-agent/tampered_payload_attack.py

demo-replay:
	docker compose exec api python apps/demo-agent/replay_attack.py

demo-overscope:
	docker compose exec api python apps/demo-agent/over_scoped_action.py

demo-expired:
	docker compose exec api python apps/demo-agent/expired_ticket.py

demo-fake:
	docker compose exec api python apps/demo-agent/fake_agent_attack.py

demo-injection:
	docker compose exec api python apps/demo-agent/injection_attack.py

demo-schema:
	docker compose exec api python apps/demo-agent/schema_violation_attack.py

demo-ratelimit:
	docker compose exec api python apps/demo-agent/rate_limit_attack.py

demo-mmr-tamper:
	docker compose exec api python apps/demo-agent/mmr_tamper_demo.py

demo-calendar:
	docker compose exec api python examples/google-calendar/run_calendar_demo.py

demo-gmail:
	docker compose exec api python examples/gmail/run_gmail_demo.py

demo-mcp:
	docker compose exec api python examples/mcp-tool/run_mcp_demo.py

logs:
	docker compose logs api -f

reset:
	docker compose down -v
	docker compose up --build -d
	docker compose exec api python scripts/seed.py

demo-full:
	@echo "============================================================"
	@echo "  LICITRA Execution Gateway — Full Attack + Use Case Suite"
	@echo "============================================================"
	docker compose exec api python apps/demo-agent/authorized_action.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/tampered_payload_attack.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/replay_attack.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/over_scoped_action.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/expired_ticket.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/fake_agent_attack.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/injection_attack.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/schema_violation_attack.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/rate_limit_attack.py
	@echo "------------------------------------------------------------"
	docker compose exec api python apps/demo-agent/mmr_tamper_demo.py
	@echo "------------------------------------------------------------"
	docker compose exec api python examples/google-calendar/run_calendar_demo.py
	@echo "------------------------------------------------------------"
	docker compose exec api python examples/gmail/run_gmail_demo.py
	@echo "------------------------------------------------------------"
	docker compose exec api python examples/mcp-tool/run_mcp_demo.py
	@echo "============================================================"
	@echo "  MMR Summary"
	@echo "============================================================"
	docker compose exec api python -c "import httpx; r = httpx.get('http://localhost:8000/audit/root'); d = r.json(); print(f'Total leaves: {d[\"leaf_count\"]}'); print(f'MMR root: {d[\"mmr_root\"]}'); print(f'Integrity: {d[\"integrity\"]}')"
