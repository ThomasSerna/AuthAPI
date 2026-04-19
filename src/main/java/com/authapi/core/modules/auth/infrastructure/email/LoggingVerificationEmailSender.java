package com.authapi.core.modules.auth.infrastructure.email;

import java.time.Instant;

import com.authapi.core.modules.auth.domain.port.VerificationEmailSender;
import com.authapi.core.modules.user.domain.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingVerificationEmailSender implements VerificationEmailSender {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingVerificationEmailSender.class);

    @Override
    public void sendEmailVerification(User user, String rawToken, Instant expiresAt) {
        LOGGER.info(
            "Email verification delivery is using the logging fallback. userId={}, email={}, expiresAt={}, token={}",
            user.getId(),
            user.getEmail(),
            expiresAt,
            rawToken
        );
    }
}
