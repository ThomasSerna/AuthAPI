package com.authapi.core.modules.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.EmailVerificationToken;
import com.authapi.core.modules.auth.domain.repository.EmailVerificationTokenRepository;

import org.springframework.stereotype.Repository;

@Repository
public class EmailVerificationTokenRepositoryAdapter implements EmailVerificationTokenRepository {

    private final JpaEmailVerificationTokenRepository jpaEmailVerificationTokenRepository;

    public EmailVerificationTokenRepositoryAdapter(
        JpaEmailVerificationTokenRepository jpaEmailVerificationTokenRepository
    ) {
        this.jpaEmailVerificationTokenRepository = jpaEmailVerificationTokenRepository;
    }

    @Override
    public Optional<EmailVerificationToken> findByIdAndTokenHash(UUID id, String tokenHash) {
        return jpaEmailVerificationTokenRepository.findByIdAndTokenHash(id, tokenHash);
    }

    @Override
    public int invalidateActiveTokensForUser(UUID userId, Instant consumedAt, Instant now) {
        return jpaEmailVerificationTokenRepository.invalidateActiveTokensForUser(userId, consumedAt, now);
    }

    @Override
    public EmailVerificationToken saveAndFlush(EmailVerificationToken token) {
        return jpaEmailVerificationTokenRepository.saveAndFlush(token);
    }
}
