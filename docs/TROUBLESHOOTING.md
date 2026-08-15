# Troubleshooting

| Symptom | Check |
|---------|--------|
| `wsl login` fails | Control reachable? `curl localhost:8080/health` |
| Connect forbidden | User in `developers` group? Policy applied? `GET /api/v1/policies` |
| No gateway for network | Gateway registered and bound to network? `GET /api/v1/gateways` |
| Peer not applied | Gateway heartbeat logs; `manage_interface` setting |
| Session stuck | Expiry / revoke; audit `GET /api/v1/audit` |

Diagnostics:

```bash
cargo run -p wsl-cli -- diagnostics
cargo run -p wsl-cli -- status
```
