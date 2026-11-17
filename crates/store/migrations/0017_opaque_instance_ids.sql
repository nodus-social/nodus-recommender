-- Instance ids become opaque text everywhere.
--
-- The id an instance uses for an account or a status is that instance's business: a
-- number on Mastodon, a ULID on nodus. The recommender only ever hands it back, so it
-- is stored verbatim and never parsed. `status.remote_id` has been the canonical key
-- since 0015; this migration finishes the job for accounts and users, and retires the
-- numeric columns plus the surrogate they forced on ingest.

-- One id per user: the account id on `instance_host`.
ALTER TABLE app_user
    ALTER COLUMN mastodon_account_id TYPE text USING mastodon_account_id::text;
ALTER TABLE app_user RENAME COLUMN mastodon_account_id TO instance_account_id;

-- Accounts carry two ids with two different jobs, and the old pair named neither well.
-- `remote_id` becomes "the id the instance we learned this account from printed", which
-- is the key every graph join already uses; the id on the account's own instance keeps
-- its old column name's meaning but moves to `origin_id`, because only a lookup against
-- the origin can reveal it.
ALTER TABLE account ADD COLUMN IF NOT EXISTS origin_id text;
UPDATE account SET origin_id = remote_id WHERE origin_id IS NULL AND remote_id IS NOT NULL;

ALTER TABLE account DROP CONSTRAINT IF EXISTS account_instance_mastodon_key;
ALTER TABLE account ALTER COLUMN mastodon_id TYPE text USING mastodon_id::text;
ALTER TABLE account DROP COLUMN IF EXISTS remote_id;
ALTER TABLE account RENAME COLUMN mastodon_id TO remote_id;
ALTER TABLE account ALTER COLUMN remote_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS account_instance_remote_key
    ON account (instance_host, remote_id);

COMMENT ON COLUMN account.remote_id IS
    'The account id as `instance_host` printed it, verbatim: numbers on Mastodon, ULIDs on nodus.';
COMMENT ON COLUMN account.origin_id IS
    'The account id on the account''s own instance, learned by lookup; null until then.';

-- One id per status: `remote_id` already carries it, and the numeric column was only
-- kept because ingest could not produce one for a ULID origin.
ALTER TABLE status DROP COLUMN IF EXISTS mastodon_id;
