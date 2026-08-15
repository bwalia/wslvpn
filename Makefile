.PHONY: dev down test fmt clippy build docs

dev:
	docker compose -f deploy/compose/docker-compose.yml up --build -d
	@echo "Control plane: http://localhost:8080"
	@echo "Swagger UI:    http://localhost:8080/swagger-ui"
	@echo "Dex:           http://localhost:5556"
	@echo "Try: cargo run -p wsl-cli -- login --email alice@example.com"

down:
	docker compose -f deploy/compose/docker-compose.yml down -v

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

build:
	cargo build --workspace

docs:
	@ls docs
