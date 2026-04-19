package com.authapi.core.modules.auth.application.password;

import java.time.Instant;
import java.util.Map;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.common.exception.ApiException;
import com.authapi.core.common.exception.ApiValidationException;
import com.authapi.core.common.security.CurrentUserService;
import com.authapi.core.modules.auth.application.support.MinimumResponseTimeService;
import com.authapi.core.modules.auth.domain.policy.PasswordPolicyService;
import com.authapi.core.modules.auth.domain.service.AuthAbuseProtectionService;
import com.authapi.core.modules.auth.domain.service.AuthAuditService;
import com.authapi.core.modules.auth.domain.service.PasswordResetService;
import com.authapi.core.modules.auth.domain.service.RefreshTokenService;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.service.UserService;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class PasswordApplicationService {

    private final CurrentUserService currentUserService;

    private final PasswordEncoder passwordEncoder;

    private final PasswordPolicyService passwordPolicyService;

    private final UserService userService;

    private final RefreshTokenService refreshTokenService;

    private final PasswordResetService passwordResetService;

    private final AuthAbuseProtectionService authAbuseProtectionService;

    private final AuthAuditService authAuditService;

    private final MinimumResponseTimeService minimumResponseTimeService;

    private final SecurityProperties securityProperties;

    public PasswordApplicationService(
        CurrentUserService currentUserService,
        PasswordEncoder passwordEncoder,
        PasswordPolicyService passwordPolicyService,
        UserService userService,
        RefreshTokenService refreshTokenService,
        PasswordResetService passwordResetService,
        AuthAbuseProtectionService authAbuseProtectionService,
        AuthAuditService authAuditService,
        MinimumResponseTimeService minimumResponseTimeService,
        SecurityProperties securityProperties
    ) {
        this.currentUserService = currentUserService;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.passwordResetService = passwordResetService;
        this.authAbuseProtectionService = authAbuseProtectionService;
        this.authAuditService = authAuditService;
        this.minimumResponseTimeService = minimumResponseTimeService;
        this.securityProperties = securityProperties;
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void changePassword(String currentPassword, String newPassword, AuthRequestMetadata requestMetadata) {
        User currentUser = currentUserService.getCurrentUserRequiringRecentReauthentication();
        if (!passwordEncoder.matches(currentPassword, currentUser.getPasswordHash())) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_CURRENT_PASSWORD",
                "Current password is incorrect."
            );
        }
        if (currentPassword.equals(newPassword)) {
            throw new ApiValidationException(
                "Request validation failed.",
                Map.of("newPassword", "New password must be different from the current password.")
            );
        }

        passwordPolicyService.validateForPasswordChange(
            newPassword,
            currentUser.getEmail(),
            currentUser.getFullName()
        );
        userService.changePassword(currentUser, passwordEncoder.encode(newPassword), Instant.now());
        refreshTokenService.revokeAllForUser(currentUser);
        authAuditService.record(
            AuthAuditEventType.PASSWORD_CHANGE,
            currentUser,
            currentUser.getEmail(),
            requestMetadata,
            "password changed by authenticated user"
        );
    }

    @Transactional
    public void forgotPassword(String email, AuthRequestMetadata requestMetadata) {
        String normalizedEmail = userService.normalizeEmail(email);
        authAbuseProtectionService.assertForgotPasswordAllowed(requestMetadata.clientIp(), normalizedEmail);
        minimumResponseTimeService.run(
            securityProperties.getPasswordReset().getRequestMinResponseTime(),
            () -> {
                authAbuseProtectionService.recordForgotPasswordAttempt(requestMetadata.clientIp(), normalizedEmail);
                passwordResetService.requestPasswordReset(email);
            }
        );
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void resetPassword(String token, String newPassword, AuthRequestMetadata requestMetadata) {
        authAbuseProtectionService.assertResetPasswordAllowed(requestMetadata.clientIp());
        minimumResponseTimeService.run(
            securityProperties.getPasswordReset().getResetMinResponseTime(),
            () -> {
                authAbuseProtectionService.recordResetPasswordAttempt(requestMetadata.clientIp());
                passwordResetService.resetPassword(token, newPassword, requestMetadata);
            }
        );
    }
}
