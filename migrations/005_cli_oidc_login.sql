-- Native-app OIDC login for the CLI and desktop client.
--
-- The browser flow ends at the control plane, which then has to hand a token
-- to a local process it cannot authenticate by connection alone. Two pieces
-- make that safe:
--
--   * the client's loopback redirect URI, recorded when the handshake starts
--     so the callback can only send the browser somewhere the client asked
--     for, and only ever to loopback;
--   * a one-time exchange code, redeemable exactly once and only by a caller
--     that can prove it started the handshake.
--
-- The proof is a PKCE-style challenge: the client keeps a random verifier and
-- sends only its SHA-256. A local process that sees the exchange code go past
-- on loopback still cannot redeem it.

ALTER TABLE oidc_auth_states
    ADD COLUMN client_redirect_uri TEXT,
    ADD COLUMN client_challenge TEXT;

COMMENT ON COLUMN oidc_auth_states.client_redirect_uri IS
    'Loopback URI to return the browser to, for native-app logins. NULL for the browser flow.';
COMMENT ON COLUMN oidc_auth_states.client_challenge IS
    'Base64url SHA-256 of the client verifier. NULL for the browser flow.';

CREATE TABLE oidc_cli_exchanges (
    -- The code is never stored: only its hash, as with access tokens.
    code_hash TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Expiry sweeps scan by time, and the window is short enough that the table
-- should stay small; the index keeps it that way if a sweep is ever missed.
CREATE INDEX idx_oidc_cli_exchanges_expires_at ON oidc_cli_exchanges (expires_at);
