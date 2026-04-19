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
import com.authapi.core.modules.auth.domain.model.EmailVerificationToken;
import com.authapi.core.modules.auth.domain.port.VerificationEmailSender;
import com.authapi.core.modules.auth.domain.repository.EmailVerificationTokenRepository;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.service.UserService;

import org.springframework.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional(readOnly = true)
public class EmailVerificationService {

    private static final Base64.Encoder TOKEN_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Logger LOGGER = LoggerFactory.getLogger(EmailVerificationService.class);

    private final SecureRandom secureRandom = new SecureRandom();

    private final EmailVerificationTokenRepository emailVerificationTokenRepository;

    private final SecurityProperties securityProperties;

    private final VerificationEmailSender verificationEmailSender;

    private final UserService userService;

    public EmailVerificationService(
        EmailVerificationTokenRepository emailVerificationTokenRepository,
        SecurityProperties securityProperties,
        VerificationEmailSender verificationEmailSender,
        UserService userService
    ) {
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
        this.securityProperties = securityProperties;
        this.verificationEmailSender = verificationEmailSender;
        this.userService = userService;
    }

    @Transactional
    public void sendVerificationFor(User user) {
        if (!user.isActive() || user.isEmailVerified()) {
            return;
        }

        Instant now = Instant.now();
        emailVerificationTokenRepository.invalidateActiveTokensForUser(user.getId(), now, now);

        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String secret = TOKEN_ENCODER.encodeToString(randomBytes);

        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(user);
        token.setTokenHash(hash(secret));
        token.setExpiresAt(now.plus(securityProperties.getEmailVerification().getTokenTtl()));
        EmailVerificationToken savedToken = emailVerificationTokenRepository.saveAndFlush(token);

        verificationEmailSender.sendEmailVerification(
            user,
            savedToken.getId() + "." + secret,
            savedToken.getExpiresAt()
        );
    }

    @Transactional
    public void requestVerification(String email) {
        userService.findByEmail(email)
            .filter(User::isActive)
            .filter(user -> !user.isEmailVerified())
            .ifPresent(user -> {
                try {
                    sendVerificationFor(user);
                } catch (RuntimeException exception) {
                    LOGGER.error(
                        "Email verification delivery failed for userId={} email={}",
                        user.getId(),
                        user.getEmail(),
                        exception
                    );
                }
            });
    }

    @Transactional
    public void confirmVerification(String rawToken) {
        EmailVerificationToken token = validate(rawToken);
        Instant now = Instant.now();
        token.setConsumedAt(now);
        userService.markEmailVerified(token.getUser(), now);
    }

    private EmailVerificationToken validate(String rawToken) {
        return resolve(rawToken).map(token -> {
            if (token.getConsumedAt() != null) {
                throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    "INVALID_EMAIL_VERIFICATION_TOKEN",
                    "Email verification token is invalid."
                );
            }
            if (!token.getExpiresAt().isAfter(Instant.now())) {
                throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    "EXPIRED_EMAIL_VERIFICATION_TOKEN",
                    "Email verification token has expired."
                );
            }
            return token;
        }).orElseThrow(() -> new ApiException(
            HttpStatus.BAD_REQUEST,
            "INVALID_EMAIL_VERIFICATION_TOKEN",
            "Email verification token is invalid."
        ));
    }

    private Optional<EmailVerificationToken> resolve(String rawToken) {
        ParsedToken parsedToken = parse(rawToken);
        if (parsedToken == null) {
            return Optional.empty();
        }
        return emailVerificationTokenRepository.findByIdAndTokenHash(parsedToken.id(), hash(parsedToken.secret()));
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
