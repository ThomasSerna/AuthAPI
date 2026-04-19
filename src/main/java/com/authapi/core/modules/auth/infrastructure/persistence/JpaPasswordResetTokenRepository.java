package com.authapi.core.modules.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.PasswordResetToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface JpaPasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByIdAndTokenHash(UUID id, String tokenHash);

    @Modifying(flushAutomatically = true)
    @Query("""
        update PasswordResetToken token
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
