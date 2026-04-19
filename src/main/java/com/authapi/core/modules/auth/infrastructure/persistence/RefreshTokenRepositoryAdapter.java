package com.authapi.core.modules.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.RefreshToken;
import com.authapi.core.modules.auth.domain.repository.RefreshTokenRepository;

import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenRepositoryAdapter implements RefreshTokenRepository {

    private final JpaRefreshTokenRepository jpaRefreshTokenRepository;

    public RefreshTokenRepositoryAdapter(JpaRefreshTokenRepository jpaRefreshTokenRepository) {
        this.jpaRefreshTokenRepository = jpaRefreshTokenRepository;
    }

    @Override
    public int revokeIfActive(UUID id, String tokenHash, Instant revokedAt, Instant now) {
        return jpaRefreshTokenRepository.revokeIfActive(id, tokenHash, revokedAt, now);
    }

    @Override
    public int revokeActiveTokensForUser(UUID userId, Instant revokedAt, Instant now) {
        return jpaRefreshTokenRepository.revokeActiveTokensForUser(userId, revokedAt, now);
    }

    @Override
    public Optional<RefreshToken> findByIdAndTokenHash(UUID id, String tokenHash) {
        return jpaRefreshTokenRepository.findByIdAndTokenHash(id, tokenHash);
    }

    @Override
    public RefreshToken save(RefreshToken token) {
        return jpaRefreshTokenRepository.save(token);
    }

    @Override
    public RefreshToken saveAndFlush(RefreshToken token) {
        return jpaRefreshTokenRepository.saveAndFlush(token);
    }
}
