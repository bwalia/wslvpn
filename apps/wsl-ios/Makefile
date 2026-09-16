# The iOS app.
#
# `make bootstrap` is required once after a clone: it fetches the pinned
# WireGuard sources and generates the Xcode project, neither of which is
# committed.

REVISION  := $(shell cat WIREGUARD_REVISION)
UPSTREAM  := Packages/WireGuardKit/upstream
SIMULATOR := platform=iOS Simulator,name=iPhone 17

.PHONY: bootstrap upstream project test build-device clean

bootstrap: upstream project

# Fetched rather than vendored or submoduled: the pin lives in
# WIREGUARD_REVISION where it can be reviewed, the repository stays free of
# third-party sources, and a Rust-only contributor never clones any of it.
upstream:
	@if [ -d "$(UPSTREAM)/.git" ] && \
	    [ "$$(git -C $(UPSTREAM) rev-parse HEAD 2>/dev/null)" = "$(REVISION)" ]; then \
		echo "wireguard-apple already at $(REVISION)"; \
	else \
		rm -rf "$(UPSTREAM)"; \
		mkdir -p "$(UPSTREAM)"; \
		git -C "$(UPSTREAM)" init -q; \
		git -C "$(UPSTREAM)" remote add origin https://git.zx2c4.com/wireguard-apple; \
		git -C "$(UPSTREAM)" fetch -q --depth 1 origin $(REVISION); \
		git -C "$(UPSTREAM)" checkout -q FETCH_HEAD; \
		for patch in $(CURDIR)/patches/*.patch; do \
			git -C "$(UPSTREAM)" apply "$$patch" || exit 1; \
			echo "applied $$(basename $$patch)"; \
		done; \
		echo "fetched wireguard-apple at $(REVISION)"; \
	fi

project:
	xcodegen generate

# Runs on a simulator, which is possible only because WSLKit does not link the
# Go library. Everything asserted here is wire format, crypto and parsing.
test:
	xcodebuild test \
		-project WSLVPN.xcodeproj \
		-scheme WSLKit \
		-destination '$(SIMULATOR)' \
		| xcbeautify 2>/dev/null || xcodebuild test \
		-project WSLVPN.xcodeproj \
		-scheme WSLKit \
		-destination '$(SIMULATOR)'

# The tunnel links libwg-go.a, which has no simulator slice, so the only way to
# compile it is for a device. Signing is off: this proves it builds, not that it
# can be installed.
build-device:
	xcodebuild build \
		-project WSLVPN.xcodeproj \
		-scheme WSLVPN \
		-destination 'generic/platform=iOS' \
		CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""

clean:
	rm -rf WSLVPN.xcodeproj $(UPSTREAM)
