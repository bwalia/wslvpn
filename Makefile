.PHONY: dev down test test-db test-db-up test-db-down fmt clippy build audit deny sbom docs

TEST_DB_CONTAINER := wslvpn-test-pg
TEST_DB_PORT      := 5434
TEST_DATABASE_URL := postgres://wsl:wsl@localhost:$(TEST_DB_PORT)/wsl

dev:
	docker compose -f deploy/compose/docker-compose.yml up --build -d
	@echo "Control plane: http://localhost:8080"
	@echo "Swagger UI:    http://localhost:8080/swagger-ui"
	@echo "Dex:           http://localhost:5556"
	@echo "Try: cargo run -p wsl-cli -- login --dev --email alice@example.com"

down:
	docker compose -f deploy/compose/docker-compose.yml down -v

# The control-plane authorization tests drive the real router against a real
# database, so they need one. `make test` brings a throwaway Postgres up, runs
# the suite, and leaves the container running for the next iteration.
test: test-db-up
	DATABASE_URL=$(TEST_DATABASE_URL) cargo test --workspace

test-db-up:
	@docker inspect -f '{{.State.Running}}' $(TEST_DB_CONTAINER) 2>/dev/null | grep -q true || ( \
		docker rm -f $(TEST_DB_CONTAINER) >/dev/null 2>&1 || true; \
		docker run -d --name $(TEST_DB_CONTAINER) \
			-e POSTGRES_USER=wsl -e POSTGRES_PASSWORD=wsl -e POSTGRES_DB=wsl \
			-p $(TEST_DB_PORT):5432 postgres:16-alpine >/dev/null; \
		printf 'waiting for postgres'; \
		for i in $$(seq 1 30); do \
			docker exec $(TEST_DB_CONTAINER) pg_isready -U wsl -d wsl >/dev/null 2>&1 && break; \
			printf '.'; sleep 1; \
		done; echo ' ready' )

test-db-down:
	-docker rm -f $(TEST_DB_CONTAINER)

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

build:
	cargo build --workspace

audit:
	cargo audit --deny warnings

deny:
	cargo deny check

sbom:
	cargo cyclonedx --format json --all

docs:
	@ls docs
