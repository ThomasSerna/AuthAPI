package com.authapi.core.modules.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.EmailVerificationToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface JpaEmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {

    Optional<EmailVerificationToken> findByIdAndTokenHash(UUID id, String tokenHash);

    @Modifying(flushAutomatically = true)
    @Query("""
        update EmailVerificationToken token
        set token.consumedAt = :consumedAt
        where token.user.id = :userId
          and token.consumedAt is null
          and token.expiresAt > :now
        """)
    int invalidateActiveTokensForUser(
        @Param("userId") UUID userId,
        @Param("consumedAt") Instant consumedAt,
        @Param("now") Instant now
    );
}
