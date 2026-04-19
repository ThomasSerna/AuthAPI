package com.authapi.core.modules.auth.domain.service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.common.exception.ApiException;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class AuthAbuseProtectionService {

    private final SecurityProperties securityProperties;

    private final Map<String, AttemptState> attempts = new ConcurrentHashMap<>();

    public AuthAbuseProtectionService(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    public void assertLoginAllowed(String clientIp, String normalizedEmail) {
        assertAllowed("login:ip:" + clientIp, securityProperties.getRateLimit().getLogin());
        assertAllowed("login:email:" + normalizedEmail, securityProperties.getRateLimit().getLogin());
    }

    public void recordLoginFailure(String clientIp, String normalizedEmail) {
        registerHit("login:ip:" + clientIp, securityProperties.getRateLimit().getLogin());
        registerHit("login:email:" + normalizedEmail, securityProperties.getRateLimit().getLogin());
    }

    public void clearLoginFailures(String clientIp, String normalizedEmail) {
        attempts.remove("login:ip:" + clientIp);
        attempts.remove("login:email:" + normalizedEmail);
    }

    public void assertForgotPasswordAllowed(String clientIp, String normalizedEmail) {
        assertAllowed("forgot:ip:" + clientIp, securityProperties.getRateLimit().getForgotPassword());
        assertAllowed("forgot:email:" + normalizedEmail, securityProperties.getRateLimit().getForgotPassword());
    }

    public void recordForgotPasswordAttempt(String clientIp, String normalizedEmail) {
        registerHit("forgot:ip:" + clientIp, securityProperties.getRateLimit().getForgotPassword());
        registerHit("forgot:email:" + normalizedEmail, securityProperties.getRateLimit().getForgotPassword());
    }

    public void assertResetPasswordAllowed(String clientIp) {
        assertAllowed("reset:ip:" + clientIp, securityProperties.getRateLimit().getResetPassword());
    }

    public void recordResetPasswordAttempt(String clientIp) {
        registerHit("reset:ip:" + clientIp, securityProperties.getRateLimit().getResetPassword());
    }

    private void assertAllowed(String key, SecurityProperties.RateLimitPolicy policy) {
        AttemptState state = attempts.get(key);
        Instant now = Instant.now();
        if (state == null) {
            return;
        }
        synchronized (state) {
            if (isExpired(state, policy, now)) {
                attempts.remove(key, state);
                return;
            }
            if (state.blockedUntil != null && state.blockedUntil.isAfter(now)) {
                throw new ApiException(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "AUTH_RATE_LIMITED",
                    "Authentication requests are temporarily blocked. Please wait and try again."
                );
            }
        }
    }

    private void registerHit(String key, SecurityProperties.RateLimitPolicy policy) {
        AttemptState state = attempts.computeIfAbsent(key, ignored -> new AttemptState());
        Instant now = Instant.now();
        synchronized (state) {
            if (isExpired(state, policy, now)) {
                state.failures = 0;
                state.blockedUntil = null;
            }
            state.failures++;
            state.lastFailureAt = now;
            if (state.failures >= policy.getThreshold()) {
                int exponent = Math.max(0, state.failures - policy.getThreshold());
                long multiplier = 1L << Math.min(exponent, 10);
                long durationMillis = Math.min(
                    policy.getBaseBlockDuration().toMillis() * multiplier,
                    policy.getMaxBlockDuration().toMillis()
                );
                state.blockedUntil = now.plusMillis(durationMillis);
            }
        }
    }

    private boolean isExpired(AttemptState state, SecurityProperties.RateLimitPolicy policy, Instant now) {
        return state.lastFailureAt != null
            && state.lastFailureAt.plus(policy.getTrackingWindow()).isBefore(now);
    }

    private static final class AttemptState {

        private int failures;

        private Instant blockedUntil;

        private Instant lastFailureAt;
    }
}
