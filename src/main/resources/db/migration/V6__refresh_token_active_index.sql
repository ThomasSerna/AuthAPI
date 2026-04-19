CREATE INDEX idx_refresh_tokens_user_active
    ON refresh_tokens (user_id, revoked_at, expires_at);
