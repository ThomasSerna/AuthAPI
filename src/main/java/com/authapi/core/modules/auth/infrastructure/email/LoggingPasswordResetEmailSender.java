package com.authapi.core.modules.auth.infrastructure.email;

import java.time.Instant;

import com.authapi.core.modules.auth.domain.port.PasswordResetEmailSender;
import com.authapi.core.modules.user.domain.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingPasswordResetEmailSender implements PasswordResetEmailSender {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingPasswordResetEmailSender.class);

    @Override
    public void sendPasswordReset(User user, String resetUrl, Instant expiresAt) {
        LOGGER.warn(
            "Password reset delivery is using the logging fallback. userId={}, email={}, expiresAt={}, resetUrl={}",
            user.getId(),
            user.getEmail(),
            expiresAt,
            resetUrl
        );
    }
}
