-- Non-HTTP services reachable from an overlay network.
--
-- The edge proxy never sees this traffic (databases, SSH, caches), so access is
-- enforced at the gateway firewall rather than by proxy rules.

CREATE TABLE network_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id UUID NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    destination CIDR NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp')),
    -- Port 0 is not assignable; 65535 is the protocol maximum. An empty array
    -- would render a firewall rule with no port, which nft rejects — and a
    -- rejected ruleset means nothing is restricted, so it is barred here.
    ports INTEGER[] NOT NULL CHECK (
        array_length(ports, 1) > 0
        AND 0 < ALL (ports)
        AND 65535 >= ALL (ports)
    ),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (network_id, name)
);

CREATE INDEX network_services_network_id_idx ON network_services (network_id);
