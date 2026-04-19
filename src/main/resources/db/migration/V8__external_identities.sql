CREATE TABLE external_identities (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    email VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL,
    last_login_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_external_identities_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE UNIQUE INDEX uk_external_identities_provider_subject ON external_identities (provider, subject);
CREATE INDEX idx_external_identities_user_id ON external_identities (user_id);
CREATE INDEX idx_external_identities_email ON external_identities (email);
