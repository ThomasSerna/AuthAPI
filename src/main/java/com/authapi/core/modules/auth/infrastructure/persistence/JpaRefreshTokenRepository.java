package com.authapi.core.modules.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.RefreshToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface JpaRefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @Modifying(flushAutomatically = true)
    @Query("""
        update RefreshToken refreshToken
        set refreshToken.revokedAt = :revokedAt
        where refreshToken.id = :id
          and refreshToken.tokenHash = :tokenHash
          and refreshToken.revokedAt is null
          and refreshToken.expiresAt > :now
        """)
    int revokeIfActive(
        @Param("id") UUID id,
        @Param("tokenHash") String tokenHash,
        @Param("revokedAt") Instant revokedAt,
        @Param("now") Instant now
    );

    @Modifying(flushAutomatically = true)
    @Query("""
        update RefreshToken refreshToken
        set refreshToken.revokedAt = :revokedAt
        where refreshToken.user.id = :userId
          and refreshToken.revokedAt is null
          and refreshToken.expiresAt > :now
        """)
    int revokeActiveTokensForUser(
        @Param("userId") UUID userId,
        @Param("revokedAt") Instant revokedAt,
        @Param("now") Instant now
    );

    Optional<RefreshToken> findByIdAndTokenHash(UUID id, String tokenHash);
}
