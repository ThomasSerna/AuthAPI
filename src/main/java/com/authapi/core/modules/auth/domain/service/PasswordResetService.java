package com.authapi.core.modules.auth.domain.service;

import java.net.URLEncoder;
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
import com.authapi.core.modules.auth.domain.model.PasswordResetToken;
import com.authapi.core.modules.auth.domain.policy.PasswordPolicyService;
import com.authapi.core.modules.auth.domain.port.PasswordResetEmailSender;
import com.authapi.core.modules.auth.domain.repository.PasswordResetTokenRepository;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.service.UserService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional(readOnly = true)
public class PasswordResetService {

    private static final Base64.Encoder TOKEN_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordResetService.class);

    private final SecureRandom secureRandom = new SecureRandom();

    private final PasswordResetTokenRepository passwordResetTokenRepository;

    private final PasswordResetEmailSender passwordResetEmailSender;

    private final SecurityProperties securityProperties;

    private final PasswordPolicyService passwordPolicyService;

    private final PasswordEncoder passwordEncoder;

    private final UserService userService;

    private final RefreshTokenService refreshTokenService;

    private final AuthAuditService authAuditService;

    private final String dummyPasswordHash;

    public PasswordResetService(
        PasswordResetTokenRepository passwordResetTokenRepository,
        PasswordResetEmailSender passwordResetEmailSender,
        SecurityProperties securityProperties,
        PasswordPolicyService passwordPolicyService,
        PasswordEncoder passwordEncoder,
        UserService userService,
        RefreshTokenService refreshTokenService,
        AuthAuditService authAuditService
    ) {
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.passwordResetEmailSender = passwordResetEmailSender;
        this.securityProperties = securityProperties;
        this.passwordPolicyService = passwordPolicyService;
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.authAuditService = authAuditService;
        this.dummyPasswordHash = passwordEncoder.encode("AuthApiDummyReset#2026");
    }

    @Transactional
    public void requestPasswordReset(String email) {
        userService.findByEmail(email)
            .filter(User::isActive)
            .ifPresentOrElse(user -> {
                try {
                    issuePasswordReset(user);
                } catch (RuntimeException exception) {
                    LOGGER.error(
                        "Password reset delivery failed for userId={} email={}",
                        user.getId(),
                        user.getEmail(),
                        exception
                    );
                }
            }, () -> simulateForgotPasswordWork(email));
    }

    @Transactional
    public boolean resetPassword(String rawToken, String newPassword, AuthRequestMetadata requestMetadata) {
        // Validate before token lookup so weak-password errors do not reveal whether a token is valid.
        passwordPolicyService.validateForPasswordReset(newPassword);

        PasswordResetToken token = resolveValid(rawToken).orElse(null);
        if (token == null) {
            simulateInvalidResetWork(rawToken, newPassword);
            return false;
        }

        User user = token.getUser();
        Instant now = Instant.now();
        token.setConsumedAt(now);
        userService.changePassword(user, passwordEncoder.encode(newPassword), now);
        refreshTokenService.revokeAllForUser(user);
        authAuditService.record(
            AuthAuditEventType.PASSWORD_RESET,
            user,
            user.getEmail(),
            requestMetadata,
            "password reset completed"
        );
        return true;
    }

    private void issuePasswordReset(User user) {
        Instant now = Instant.now();
        passwordResetTokenRepository.invalidateActiveTokensForUser(user.getId(), now, now);

        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String secret = TOKEN_ENCODER.encodeToString(randomBytes);

        PasswordResetToken token = new PasswordResetToken();
        token.setUser(user);
        token.setTokenHash(hash(secret));
        token.setExpiresAt(now.plus(securityProperties.getPasswordReset().getTokenTtl()));
        PasswordResetToken savedToken = passwordResetTokenRepository.saveAndFlush(token);
        String rawToken = savedToken.getId() + "." + secret;

        passwordResetEmailSender.sendPasswordReset(
            user,
            buildResetUrl(rawToken),
            savedToken.getExpiresAt()
        );
    }

    private void simulateForgotPasswordWork(String email) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String secret = TOKEN_ENCODER.encodeToString(randomBytes);
        hash(secret + userService.normalizeEmail(email));
        buildResetUrl(UUID.randomUUID() + "." + secret);
    }

    private void simulateInvalidResetWork(String rawToken, String newPassword) {
        ParsedToken parsedToken = parse(rawToken);
        if (parsedToken != null) {
            hash(parsedToken.secret());
        } else if (StringUtils.hasText(rawToken)) {
            hash(rawToken.trim());
        } else {
            hash("missing-reset-token");
        }
        passwordEncoder.matches(newPassword, dummyPasswordHash);
    }

    private String buildResetUrl(String rawToken) {
        String template = securityProperties.getPasswordReset().getResetUrlTemplate();
        String encodedToken = URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
        if (!StringUtils.hasText(template)) {
            return encodedToken;
        }
        if (template.contains("{token}")) {
            return template.replace("{token}", encodedToken);
        }
        return template.contains("?")
            ? template + "&token=" + encodedToken
            : template + "?token=" + encodedToken;
    }

    private Optional<PasswordResetToken> resolveValid(String rawToken) {
        ParsedToken parsedToken = parse(rawToken);
        if (parsedToken == null) {
            return Optional.empty();
        }
        return passwordResetTokenRepository.findByIdAndTokenHash(parsedToken.id(), hash(parsedToken.secret()))
            .filter(token -> token.getConsumedAt() == null)
            .filter(token -> token.getExpiresAt().isAfter(Instant.now()));
    }

    private ParsedToken parse(String rawToken) {
        if (!StringUtils.hasText(rawToken)) {
            return null;
        }
        String[] tokenParts = rawToken.split("\\.", 2);
        if (tokenParts.length != 2 || !StringUtils.hasText(tokenParts[0]) || !StringUtils.hasText(tokenParts[1])) {
            return null;
        }
        try {
            return new ParsedToken(UUID.fromString(tokenParts[0]), tokenParts[1]);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private String hash(String value) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(messageDigest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available in this runtime.", exception);
        }
    }

    private record ParsedToken(UUID id, String secret) {
    }
}
