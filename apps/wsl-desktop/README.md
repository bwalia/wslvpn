# WSL Zero Trust — Desktop (macOS)

Minimal Tauri shell over `wsl-agent` / CLI. The GUI never runs as root.

## Dev

```bash
cd apps/wsl-desktop
npm install
npm run tauri dev
```

Requires Rust toolchain and macOS for native builds.

## UX

1. Sign in
2. Show user, device trust, networks
3. Disconnect all
