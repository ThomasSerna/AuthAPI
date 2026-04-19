ALTER TABLE users
    ADD COLUMN email_verified_at TIMESTAMP NULL;

ALTER TABLE users
    ADD COLUMN password_changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;

UPDATE users
SET
    email_verified_at = COALESCE(email_verified_at, created_at),
    password_changed_at = COALESCE(password_changed_at, updated_at, created_at);

CREATE TABLE email_verification_tokens (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_email_verification_tokens_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE UNIQUE INDEX uk_email_verification_tokens_hash ON email_verification_tokens (token_hash);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens (user_id);
