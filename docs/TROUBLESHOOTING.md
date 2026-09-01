# Troubleshooting

| Symptom | Check |
|---------|--------|
| `wsl login` fails | Control reachable? `curl localhost:8080/health` |
| Connect forbidden | User in `developers` group? Policy applied? `GET /api/v1/policies` |
| No gateway for network | Gateway registered and bound to network? `GET /api/v1/gateways` |
| Peer not applied | Gateway heartbeat logs; `manage_interface` setting |
| Session stuck | Expiry / revoke; audit `GET /api/v1/audit` |

## Authorization

Every route under `/api/v1` and `/SCIM/v2` needs a credential — see
[AUTHORIZATION.md](AUTHORIZATION.md). If you are upgrading from a build where
they did not, start with [UPGRADING.md](UPGRADING.md).

| Response | Meaning | Fix |
|---|---|---|
| `401` on `/api/v1/*` | No credential, an expired one, or a disabled account | Sign in again; check `users.active` |
| `403` on an admin route | Authenticated, but `role = 'member'` | Add the address to `bootstrap.admin_emails` and restart |
| `404` on someone else's resource | Deliberate — "not yours" is indistinguishable from "not there" | Use an admin credential |
| `401` from SCIM | The IdP is not sending `scim_service_token` | Set it in the Secret and in the IdP connector |
| `401` on gateway heartbeat | The credential was rotated, or the gateway record was recreated | The gateway re-enrolls on its own if it still holds the shared enrollment secret |
| `403` on gateway register | The name exists and this host cannot prove possession of its credential | Rotate as an admin, or enroll under a different name |
| `429` | Over the rate-limit budget | Check `retry-after`; the budget is per replica |

## The control plane will not start

Every startup validation names itself in the error.

| Error mentions | Cause |
|---|---|
| `unset environment variable` | A `${VAR}` in the config with no value in the environment |
| `still holds its example value` | A shipped example secret on a non-loopback deployment |
| `dev_login_enabled must be false` | The development back door is on for a public host |
| `admin_emails must name at least one` | Nobody would be able to administer the deployment |
| `database.url must be a postgres URL` | Wrong scheme, or an unexpanded placeholder |

## Diagnostics

```bash
cargo run -p wsl-cli -- diagnostics
cargo run -p wsl-cli -- status

# Is this replica able to serve?
curl -s localhost:8080/readyz

# Does the audit chain still verify?
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" localhost:8080/api/v1/audit/verify
```

Failed authorization is logged as a `denied:` warning with the path and the
principal, so the control plane's structured logs will say which rule refused a
request and why.
