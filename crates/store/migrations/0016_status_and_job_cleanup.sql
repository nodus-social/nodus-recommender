-- Drop the legacy (instance_host, mastodon_id) unique constraint on status now
-- that status_instance_remote_key (instance_host, remote_id) is the canonical key.
ALTER TABLE status DROP CONSTRAINT IF EXISTS status_instance_mastodon_key;

-- Allow pending jobs to be cancelled when a user deletes their account or
-- disables background sync.
ALTER TABLE job DROP CONSTRAINT job_status_valid;
ALTER TABLE job ADD CONSTRAINT job_status_valid
    CHECK (status IN ('pending', 'running', 'done', 'failed', 'cancelled'));
