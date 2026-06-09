.PHONY: setup up down test seed \
        demo-authorized demo-tamper demo-replay \
        demo-overscope demo-expired demo-fake \
        demo-injection demo-schema demo-ratelimit \
        demo-mmr-tamper demo-calendar demo-gmail \
        demo-mcp demo-full

setup:
	cp -n .env.example .env || true

up:
	docker compose up --build -d

down:
	docker compose down

test:
	docker compose exec api pytest tests/ -v

seed:
	@echo "seed: not yet implemented"

demo-authorized:
	@echo "demo-authorized: not yet implemented"

demo-tamper:
	@echo "demo-tamper: not yet implemented"

demo-replay:
	@echo "demo-replay: not yet implemented"

demo-overscope:
	@echo "demo-overscope: not yet implemented"

demo-expired:
	@echo "demo-expired: not yet implemented"

demo-fake:
	@echo "demo-fake: not yet implemented"

demo-injection:
	@echo "demo-injection: not yet implemented"

demo-schema:
	@echo "demo-schema: not yet implemented"

demo-ratelimit:
	@echo "demo-ratelimit: not yet implemented"

demo-mmr-tamper:
	@echo "demo-mmr-tamper: not yet implemented"

demo-calendar:
	@echo "demo-calendar: not yet implemented"

demo-gmail:
	@echo "demo-gmail: not yet implemented"

demo-mcp:
	@echo "demo-mcp: not yet implemented"

demo-full:
	@echo "demo-full: not yet implemented"
