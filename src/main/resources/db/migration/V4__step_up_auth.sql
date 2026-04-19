ALTER TABLE users
    ADD COLUMN session_version INT NOT NULL DEFAULT 0;

UPDATE users
SET session_version = COALESCE(session_version, 0);
