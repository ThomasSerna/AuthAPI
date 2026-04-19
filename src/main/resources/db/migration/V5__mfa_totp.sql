ALTER TABLE users
    ADD COLUMN mfa_totp_secret_ciphertext VARCHAR(1024) NULL;

ALTER TABLE users
    ADD COLUMN mfa_totp_pending_secret_ciphertext VARCHAR(1024) NULL;

ALTER TABLE users
    ADD COLUMN mfa_totp_enabled_at TIMESTAMP NULL;
