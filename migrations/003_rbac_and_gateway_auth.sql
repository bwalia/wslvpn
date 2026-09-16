-- Role-based access control and per-gateway credentials.
--
-- Before this migration every /api/v1 route was reachable anonymously. Two
-- things are needed to close that: a way to tell an administrator from an
-- ordinary member, and a credential a gateway can prove possession of so that
-- pulling a GatewayConfig is no longer a matter of knowing a UUID.

-- Roles ---------------------------------------------------------------------
-- 'member' is the safe default: an existing user picked up by this migration
-- gets the lowest privilege, and admins are granted explicitly at bootstrap
-- from config.security.admin_emails.
ALTER TABLE users
    ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
    CHECK (role IN ('admin', 'member'));

CREATE INDEX users_role_idx ON users (role) WHERE role = 'admin';

-- Per-gateway credentials ---------------------------------------------------
-- registration_token_hash records which enrollment secret let this gateway in.
-- auth_token_hash is the gateway's own long-lived credential, minted at
-- enrollment and presented on every config/heartbeat call. It is nullable so
-- gateways enrolled before this migration keep working until they re-enroll.
ALTER TABLE gateways
    ADD COLUMN auth_token_hash TEXT UNIQUE,
    ADD COLUMN auth_token_rotated_at TIMESTAMPTZ;

-- Service token scopes ------------------------------------------------------
-- SCIM provisioning is a distinct capability from ops provisioning: an IdP's
-- SCIM credential should not also be able to read the audit log.
ALTER TABLE service_tokens
    ADD COLUMN description TEXT,
    ADD COLUMN expires_at TIMESTAMPTZ;

CREATE INDEX service_tokens_active_idx ON service_tokens (active) WHERE active;
