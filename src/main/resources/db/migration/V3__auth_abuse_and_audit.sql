CREATE TABLE password_reset_tokens (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE UNIQUE INDEX uk_password_reset_tokens_hash ON password_reset_tokens (token_hash);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);

CREATE TABLE auth_audit_events (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) NULL,
    email VARCHAR(255) NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(128) NULL,
    user_agent VARCHAR(512) NULL,
    details VARCHAR(1024) NULL,
    occurred_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_auth_audit_events_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX idx_auth_audit_events_type ON auth_audit_events (event_type);
CREATE INDEX idx_auth_audit_events_user_id ON auth_audit_events (user_id);
