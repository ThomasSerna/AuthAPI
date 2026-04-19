package com.authapi.core.modules.auth.domain.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.auth.domain.model.RefreshToken;
import com.authapi.core.modules.auth.domain.repository.RefreshTokenRepository;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import com.authapi.core.modules.user.domain.model.User;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional(readOnly = true)
public class RefreshTokenService {

    private static final Base64.Encoder TOKEN_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final SecureRandom secureRandom = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;

    private final SecurityProperties securityProperties;

    private final AuthAuditService authAuditService;

    public RefreshTokenService(
        RefreshTokenRepository refreshTokenRepository,
        SecurityProperties securityProperties,
        AuthAuditService authAuditService
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.securityProperties = securityProperties;
        this.authAuditService = authAuditService;
    }

    @Transactional
    public RefreshSession issue(User user) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String secret = TOKEN_ENCODER.encodeToString(randomBytes);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hash(secret));
        refreshToken.setExpiresAt(Instant.now().plus(securityProperties.getJwt().getRefreshTokenTtl()));
        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
        if (savedToken.getId() == null) {
            savedToken = refreshTokenRepository.saveAndFlush(refreshToken);
        }
        String rawToken = savedToken.getId() + "." + secret;
        return new RefreshSession(user, rawToken, savedToken.getExpiresAt());
    }

    @Transactional
    public RefreshSession rotate(String rawToken, AuthRequestMetadata requestMetadata) {
        ParsedRefreshToken parsedToken = requireParsedToken(rawToken);
        RefreshToken refreshToken = requireToken(parsedToken);
        Instant now = Instant.now();

        int updatedRows = refreshTokenRepository.revokeIfActive(
            parsedToken.id(),
            hash(parsedToken.secret()),
            now,
            now
        );
        if (updatedRows == 0) {
            RefreshToken currentToken = requireToken(parsedToken);
            if (currentToken.getRevokedAt() != null) {
                authAuditService.record(
                    AuthAuditEventType.REFRESH_REUSE,
                    currentToken.getUser(),
                    currentToken.getUser().getEmail(),
                    requestMetadata,
                    "revoked refresh token reused"
                );
                throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", "Invalid refresh token.");
            }
            if (!currentToken.getExpiresAt().isAfter(now)) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "EXPIRED_REFRESH_TOKEN", "Refresh token has expired.");
            }
            throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", "Invalid refresh token.");
        }

        return issue(refreshToken.getUser());
    }

    @Transactional
    public void revoke(String rawToken) {
        if (!StringUtils.hasText(rawToken)) {
            return;
        }
        resolve(rawToken).ifPresent(refreshToken -> {
            if (refreshToken.getRevokedAt() == null && refreshToken.getExpiresAt().isAfter(Instant.now())) {
                refreshToken.setRevokedAt(Instant.now());
                refreshTokenRepository.save(refreshToken);
            }
        });
    }

    @Transactional
    public void revokeAllForUser(User user) {
        Instant now = Instant.now();
        refreshTokenRepository.revokeActiveTokensForUser(user.getId(), now, now);
    }

    public User getUserForRefresh(String rawToken) {
        return validate(rawToken).getUser();
    }

    public Optional<User> findUser(String rawToken) {
        return resolve(rawToken).map(RefreshToken::getUser);
    }

    private RefreshToken validate(String rawToken) {
        return resolve(rawToken).map(token -> {
            if (token.getRevokedAt() != null) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", "Invalid refresh token.");
            }
            if (!token.getExpiresAt().isAfter(Instant.now())) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "EXPIRED_REFRESH_TOKEN", "Refresh token has expired.");
            }
            return token;
        }).orElseThrow(() -> new ApiException(
            HttpStatus.UNAUTHORIZED,
            "INVALID_REFRESH_TOKEN",
            "Invalid refresh token."
        ));
    }

    private Optional<RefreshToken> resolve(String rawToken) {
        ParsedRefreshToken parsedToken = parse(rawToken);
        if (parsedToken == null) {
            return Optional.empty();
        }
        return refreshTokenRepository.findByIdAndTokenHash(parsedToken.id(), hash(parsedToken.secret()));
    }

    private ParsedRefreshToken parse(String rawToken) {
        if (!StringUtils.hasText(rawToken)) {
            return null;
        }
        String[] tokenParts = rawToken.split("\\.", 2);
        if (tokenParts.length != 2 || !StringUtils.hasText(tokenParts[0]) || !StringUtils.hasText(tokenParts[1])) {
            return null;
        }
        try {
            return new ParsedRefreshToken(UUID.fromString(tokenParts[0]), tokenParts[1]);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private ParsedRefreshToken requireParsedToken(String rawToken) {
        ParsedRefreshToken parsedToken = parse(rawToken);
        if (parsedToken == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", "Invalid refresh token.");
        }
        return parsedToken;
    }

    private RefreshToken requireToken(ParsedRefreshToken parsedToken) {
        return refreshTokenRepository.findByIdAndTokenHash(parsedToken.id(), hash(parsedToken.secret()))
            .orElseThrow(() -> new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_REFRESH_TOKEN",
                "Invalid refresh token."
            ));
    }

    private String hash(String value) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(messageDigest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available in this runtime.", exception);
        }
    }

    public record RefreshSession(User user, String token, Instant expiresAt) {
    }

    private record ParsedRefreshToken(UUID id, String secret) {
    }
}
