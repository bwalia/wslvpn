# SCIM

SCIM 2.0 surface for IdP provisioning into WSL.

## Endpoints

- `GET /SCIM/v2/ServiceProviderConfig`
- `GET /SCIM/v2/ResourceTypes`
- `GET /SCIM/v2/Schemas`
- `GET|POST /SCIM/v2/Users`
- `GET|PUT|PATCH|DELETE /SCIM/v2/Users/{id}`
- `GET|POST /SCIM/v2/Groups`
- `GET|DELETE /SCIM/v2/Groups/{id}`

Supports create, update, patch (active/displayName), delete, activate/deactivate.

SCIM is the preferred long-term lifecycle path alongside OpsAPI provisioning.
