-- Tamper-evident audit log and attribution of the acting principal.
--
-- Two gaps this closes. First, an audit_events row recorded *what* happened but
-- not *who* asked for it, so an administrative action could not be attributed
-- to the credential that performed it. Second, the table was ordinary rows:
-- anyone with UPDATE or DELETE on the database could rewrite history and leave
-- no trace, which is the one property an audit log has to have.

-- Attribution ----------------------------------------------------------------
-- actor_type distinguishes a signed-in human from a service credential from the
-- system itself, and actor_id names which one. user_id keeps its meaning as the
-- *subject* of the event, which is often a different person from the actor.
ALTER TABLE audit_events
    ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'system'
        CHECK (actor_type IN ('user', 'service', 'gateway', 'system')),
    ADD COLUMN actor_id TEXT,
    ADD COLUMN source_ip INET,
    ADD COLUMN request_id TEXT;

CREATE INDEX audit_events_actor_idx ON audit_events (actor_type, actor_id, created_at DESC);
CREATE INDEX audit_events_action_idx ON audit_events (action, created_at DESC);

-- Tamper evidence ------------------------------------------------------------
-- Each row carries the hash of the row before it, so the log is a chain. An
-- altered or removed row breaks every hash after it, and a verifier walking the
-- chain finds the exact point where it diverges.
--
-- This detects tampering; it does not prevent it. Prevention is a matter of not
-- granting UPDATE or DELETE on this table and of shipping the log somewhere the
-- database's owner cannot reach. See docs/OPERATIONS.md.
ALTER TABLE audit_events
    ADD COLUMN seq BIGINT,
    ADD COLUMN prev_hash TEXT,
    ADD COLUMN entry_hash TEXT;

-- One definition of the hash, used by both the backfill below and the trigger,
-- so the two can never drift apart and start disagreeing about what a valid
-- chain looks like.
CREATE OR REPLACE FUNCTION audit_entry_hash(p_prev TEXT, p_seq BIGINT, e audit_events)
RETURNS TEXT AS $$
    SELECT encode(
        digest(
            p_prev ||
            p_seq::text || '|' ||
            e.action || '|' ||
            COALESCE(e.decision, '') || '|' ||
            e.actor_type || '|' ||
            COALESCE(e.actor_id, '') || '|' ||
            COALESCE(e.user_id::text, '') || '|' ||
            COALESCE(e.device_id::text, '') || '|' ||
            COALESCE(e.resource, '') || '|' ||
            COALESCE(e.policy_id::text, '') || '|' ||
            COALESCE(e.policy_version::text, '') || '|' ||
            COALESCE(e.git_commit, '') || '|' ||
            COALESCE(e.source_ip::text, '') || '|' ||
            COALESCE(e.request_id, '') || '|' ||
            e.details::text || '|' ||
            e.created_at::text,
            'sha256'
        ),
        'hex'
    );
$$ LANGUAGE sql IMMUTABLE;

-- Chain any rows written before this migration, so verification starts from the
-- beginning of the log rather than from the moment integrity was switched on.
DO $$
DECLARE
    row_record audit_events%ROWTYPE;
    next_seq BIGINT := 0;
    previous TEXT := repeat('0', 64);
    computed TEXT;
BEGIN
    FOR row_record IN
        SELECT * FROM audit_events ORDER BY created_at, id
    LOOP
        next_seq := next_seq + 1;
        computed := audit_entry_hash(previous, next_seq, row_record);
        UPDATE audit_events
        SET seq = next_seq, prev_hash = previous, entry_hash = computed
        WHERE id = row_record.id;
        previous := computed;
    END LOOP;
END;
$$;

-- Assign `seq` inside the trigger under a transaction-scoped advisory lock
-- rather than from a sequence.
--
-- A BIGSERIAL would be wrong here: nextval is called when the row is built, but
-- the chain has to follow *commit* order. Two concurrent writers can take
-- numbers 4 and 5 and commit in the other order, and each would then chain off
-- whatever was visible to it — forking the chain and making verification fail
-- on a log nobody tampered with. The advisory lock serialises writers so the
-- number and the link are decided together.
CREATE OR REPLACE FUNCTION audit_events_chain()
RETURNS TRIGGER AS $$
DECLARE
    previous TEXT;
    previous_seq BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('wsl_audit_events_chain'));

    SELECT seq, entry_hash INTO previous_seq, previous
    FROM audit_events
    ORDER BY seq DESC
    LIMIT 1;

    NEW.seq := COALESCE(previous_seq, 0) + 1;
    NEW.prev_hash := COALESCE(previous, repeat('0', 64));
    NEW.entry_hash := audit_entry_hash(NEW.prev_hash, NEW.seq, NEW);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_chain_trigger
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_chain();

ALTER TABLE audit_events
    ALTER COLUMN seq SET NOT NULL,
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN entry_hash SET NOT NULL;

CREATE UNIQUE INDEX audit_events_seq_idx ON audit_events (seq);

-- Refuse in-place edits outright. A correction to the audit log is a new event
-- describing the correction, never an overwrite of the original.
CREATE OR REPLACE FUNCTION audit_events_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only; % is not permitted', TG_OP
        USING HINT = 'record a correcting event instead of altering history';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

CREATE TRIGGER audit_events_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

-- Verification ---------------------------------------------------------------
-- Walk the chain and report the first row whose recorded hash disagrees with
-- the hash of its own contents, or whose link does not match its predecessor.
-- An empty result means the log is intact.
CREATE OR REPLACE FUNCTION audit_verify()
RETURNS TABLE (seq BIGINT, id UUID, created_at TIMESTAMPTZ, problem TEXT) AS $$
DECLARE
    row_record audit_events%ROWTYPE;
    previous TEXT := repeat('0', 64);
    expected_seq BIGINT := 0;
BEGIN
    FOR row_record IN SELECT * FROM audit_events ORDER BY seq LOOP
        expected_seq := expected_seq + 1;
        IF row_record.seq <> expected_seq THEN
            seq := row_record.seq;
            id := row_record.id;
            created_at := row_record.created_at;
            problem := format('gap in sequence: expected %s', expected_seq);
            RETURN NEXT;
            RETURN;
        END IF;
        IF row_record.prev_hash <> previous THEN
            seq := row_record.seq;
            id := row_record.id;
            created_at := row_record.created_at;
            problem := 'link does not match the preceding entry';
            RETURN NEXT;
            RETURN;
        END IF;
        IF row_record.entry_hash
           <> audit_entry_hash(row_record.prev_hash, row_record.seq, row_record) THEN
            seq := row_record.seq;
            id := row_record.id;
            created_at := row_record.created_at;
            problem := 'contents do not match the recorded hash';
            RETURN NEXT;
            RETURN;
        END IF;
        previous := row_record.entry_hash;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Retention ------------------------------------------------------------------
-- Deletion is blocked by the trigger above, so trimming the log is a deliberate
-- act: export, disable the trigger, trim, re-enable, and record that it
-- happened. The runbook is in docs/OPERATIONS.md. This view gives an operator
-- the boundaries to work from without having to derive them.
CREATE VIEW audit_retention AS
SELECT
    min(created_at) AS oldest_event,
    max(created_at) AS newest_event,
    count(*)        AS event_count,
    pg_size_pretty(pg_total_relation_size('audit_events')) AS on_disk
FROM audit_events;
