# The desktop app ships the `wsl` CLI inside its bundle, as a Tauri sidecar,
# so a released app never depends on - or silently picks up a different
# version of - whatever `wsl` is on the user's PATH.
#
#   make test   view logic (node) + bridge (cargo)
#   make dev    run against a debug CLI
#   make app    release .app under src-tauri/target/release/bundle/macos
#   make dmg    the same, as a .dmg (drives Finder, so needs a GUI session)

.PHONY: deps cli test dev app dmg clean

ROOT   := $(abspath ../..)
TRIPLE := $(shell rustc -vV | sed -n 's/^host: //p')
SIDECAR := src-tauri/binaries/wsl-$(TRIPLE)

deps:
	npm ci

# Tauri resolves externalBin "binaries/wsl" to binaries/wsl-<target-triple>
# and installs it next to the app's executable, where the bridge looks first.
cli:
	cargo build --release -p wsl-cli --manifest-path $(ROOT)/Cargo.toml
	mkdir -p src-tauri/binaries
	install -m 0755 $(ROOT)/target/release/wsl $(SIDECAR)

test: deps
	npm test
	@test -e $(SIDECAR) || { mkdir -p src-tauri/binaries && : > $(SIDECAR); }
	cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings

dev: deps
	cargo build -p wsl-cli --manifest-path $(ROOT)/Cargo.toml
	@test -e $(SIDECAR) || { mkdir -p src-tauri/binaries && : > $(SIDECAR); }
	WSL_CLI=$(ROOT)/target/debug/wsl npx tauri dev

app: deps cli
	npx tauri build

dmg: deps cli
	npx tauri build --bundles dmg

clean:
	rm -rf dist src-tauri/binaries
