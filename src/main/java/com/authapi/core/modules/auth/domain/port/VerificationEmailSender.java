package com.authapi.core.modules.auth.domain.port;

import java.time.Instant;

import com.authapi.core.modules.user.domain.model.User;

public interface VerificationEmailSender {

    void sendEmailVerification(User user, String rawToken, Instant expiresAt);
}
