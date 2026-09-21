-- Bind a login to the identity provider's stable subject, not to an email.
--
-- Until now the callback read the `email` claim out of the id_token and upserted
-- a user on it. Two things were wrong with that:
--
--   * An email address is a mutable attribute. A directory that reassigns one
--     — a renamed person, a recycled contractor address — silently hands the
--     new holder the old holder's access, because the email *is* the key.
--   * `bootstrap.admin_emails` grants the admin role by email address. So any
--     token carrying an administrator's address became an administrator.
--
-- The provider's `sub` claim is the stable identifier and is unique only within
-- the issuer, so the binding is on the pair. `email` is still recorded, as a
-- last-seen attribute for audit and display — never as an authorization key.

CREATE TABLE oidc_identities (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Last email this subject presented. Mutable; for display and audit only.
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (issuer, subject)
);

COMMENT ON TABLE oidc_identities IS
    'Stable (issuer, subject) -> user binding. Authoritative for who a login is.';
COMMENT ON COLUMN oidc_identities.email IS
    'Last email seen for this subject. Display and audit only, never an authorization key.';

-- One issuer must not hold two subjects for the same person: that is the shape
-- an account-takeover attempt takes, where an attacker registers a second
-- account at the provider carrying a victim's email. The constraint turns that
-- into a refused login instead of a silent merge.
CREATE UNIQUE INDEX idx_oidc_identities_issuer_user ON oidc_identities (issuer, user_id);

CREATE INDEX idx_oidc_identities_user_id ON oidc_identities (user_id);

-- Replay protection for the id_token, carried through the handshake.
--
-- The nonce is generated when the authorize request is made and must come back
-- inside the signed id_token. A token minted for a different handshake — a
-- previously captured one, or one obtained from the provider out of band —
-- carries the wrong nonce and is refused.
ALTER TABLE oidc_auth_states ADD COLUMN nonce TEXT;

COMMENT ON COLUMN oidc_auth_states.nonce IS
    'Random value echoed in the id_token nonce claim, binding the token to this handshake.';
