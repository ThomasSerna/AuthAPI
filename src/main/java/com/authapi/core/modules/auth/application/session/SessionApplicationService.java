package com.authapi.core.modules.auth.application.session;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;

import com.authapi.core.common.exception.ApiException;
import com.authapi.core.common.security.CurrentUserService;
import com.authapi.core.modules.auth.domain.policy.PasswordPolicyService;
import com.authapi.core.modules.auth.domain.service.AuthAbuseProtectionService;
import com.authapi.core.modules.auth.domain.service.AuthAuditService;
import com.authapi.core.modules.auth.domain.service.EmailVerificationService;
import com.authapi.core.modules.auth.domain.service.ExternalIdentityService;
import com.authapi.core.modules.auth.domain.service.FederatedIdentityVerifier;
import com.authapi.core.modules.auth.domain.service.MfaTotpService;
import com.authapi.core.modules.auth.domain.service.RefreshTokenService;
import com.authapi.core.modules.auth.domain.service.TokenService;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;
import com.authapi.core.modules.auth.domain.support.FederatedIdentity;
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
public class SessionApplicationService {

    private static final String TOKEN_TYPE = "Bearer";
    private static final Base64.Encoder PLACEHOLDER_PASSWORD_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    private final TokenService tokenService;

    private final RefreshTokenService refreshTokenService;

    private final CurrentUserService currentUserService;

    private final PasswordPolicyService passwordPolicyService;

    private final EmailVerificationService emailVerificationService;

    private final MfaTotpService mfaTotpService;

    private final AuthAbuseProtectionService authAbuseProtectionService;

    private final AuthAuditService authAuditService;

    private final FederatedIdentityVerifier federatedIdentityVerifier;

    private final ExternalIdentityService externalIdentityService;

    private final SecureRandom secureRandom = new SecureRandom();

    public SessionApplicationService(
            UserService userService,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            RefreshTokenService refreshTokenService,
            CurrentUserService currentUserService,
            PasswordPolicyService passwordPolicyService,
            EmailVerificationService emailVerificationService,
            MfaTotpService mfaTotpService,
            AuthAbuseProtectionService authAbuseProtectionService,
            AuthAuditService authAuditService,
            FederatedIdentityVerifier federatedIdentityVerifier,
            ExternalIdentityService externalIdentityService) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
        this.currentUserService = currentUserService;
        this.passwordPolicyService = passwordPolicyService;
        this.emailVerificationService = emailVerificationService;
        this.mfaTotpService = mfaTotpService;
        this.authAbuseProtectionService = authAbuseProtectionService;
        this.authAuditService = authAuditService;
        this.federatedIdentityVerifier = federatedIdentityVerifier;
        this.externalIdentityService = externalIdentityService;
    }

    @Transactional
    public AuthenticatedSession register(String email, String password, String fullName) {
        passwordPolicyService.validateForRegistration(password, email, fullName);
        User user = userService.registerNewUser(email, passwordEncoder.encode(password), fullName);
        emailVerificationService.sendVerificationFor(user);
        return authenticate(userService.getRequiredUser(user.getId()));
    }

    @Transactional
    public AuthenticatedSession login(
            String email,
            String password,
            String mfaCode,
            AuthRequestMetadata requestMetadata) {
        String normalizedEmail = userService.normalizeEmail(email);
        authAbuseProtectionService.assertLoginAllowed(requestMetadata.clientIp(), normalizedEmail);

        User user = userService.findByEmail(email).orElse(null);
        if (user == null
                || !user.isActive()
                || !passwordEncoder.matches(password, user.getPasswordHash())
                || !user.isEmailVerified()) {
            authAbuseProtectionService.recordLoginFailure(requestMetadata.clientIp(), normalizedEmail);
            authAuditService.record(
                    AuthAuditEventType.LOGIN_FAILURE,
                    user,
                    normalizedEmail,
                    requestMetadata,
                    user != null && !user.isEmailVerified() ? "email not verified" : "invalid credentials");
            throw invalidLoginException();
        }

        if (user.isTotpMfaEnabled()) {
            if (!hasText(mfaCode)) {
                throw new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        "MFA_REQUIRED",
                        "Multi-factor authentication code is required.");
            }
            if (!mfaTotpService.isCodeValidForUser(user, mfaCode)) {
                authAbuseProtectionService.recordLoginFailure(requestMetadata.clientIp(), normalizedEmail);
                authAuditService.record(
                        AuthAuditEventType.MFA_FAILURE,
                        user,
                        user.getEmail(),
                        requestMetadata,
                        "invalid totp code during login");
                throw invalidMfaCodeException();
            }
        }

        maybeUpgradePasswordHash(user, password);
        authAbuseProtectionService.clearLoginFailures(requestMetadata.clientIp(), normalizedEmail);
        authAuditService.record(
                AuthAuditEventType.LOGIN_SUCCESS,
                user,
                user.getEmail(),
                requestMetadata,
                "login successful");
        return authenticate(user);
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public AuthenticatedSession loginWithGoogle(
            String idToken,
            String mfaCode,
            AuthRequestMetadata requestMetadata) {
        return loginWithFederatedProvider(FederatedAuthProvider.GOOGLE, idToken, mfaCode, requestMetadata);
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public AuthenticatedSession loginWithMicrosoft(
            String idToken,
            String mfaCode,
            AuthRequestMetadata requestMetadata) {
        return loginWithFederatedProvider(FederatedAuthProvider.MICROSOFT, idToken, mfaCode, requestMetadata);
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public AuthenticatedSession refresh(String refreshToken, AuthRequestMetadata requestMetadata) {
        requireVerifiedEmail(refreshTokenService.getUserForRefresh(refreshToken));
        RefreshTokenService.RefreshSession refreshSession = refreshTokenService.rotate(refreshToken, requestMetadata);
        TokenService.AccessToken accessToken = tokenService.issueAccessToken(refreshSession.user());
        return new AuthenticatedSession(
                TOKEN_TYPE,
                accessToken.token(),
                accessToken.expiresAt(),
                refreshSession.token(),
                refreshSession.expiresAt(),
                refreshSession.user());
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void logout(String refreshToken, AuthRequestMetadata requestMetadata) {
        refreshTokenService.findUser(refreshToken).ifPresent(user -> authAuditService.record(
                AuthAuditEventType.LOGOUT,
                user,
                user.getEmail(),
                requestMetadata,
                "logout successful"));
        refreshTokenService.revoke(refreshToken);
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public AuthenticatedSession reauthenticate(
            String password,
            String mfaCode,
            AuthRequestMetadata requestMetadata) {
        User currentUser = currentUserService.getCurrentUser();
        if (!passwordEncoder.matches(password, currentUser.getPasswordHash())) {
            authAuditService.record(
                    AuthAuditEventType.STEP_UP_FAILURE,
                    currentUser,
                    currentUser.getEmail(),
                    requestMetadata,
                    "invalid password during reauthentication");
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "INVALID_REAUTHENTICATION",
                    "Password is incorrect.");
        }
        if (currentUser.isTotpMfaEnabled()) {
            if (!hasText(mfaCode)) {
                authAuditService.record(
                        AuthAuditEventType.STEP_UP_FAILURE,
                        currentUser,
                        currentUser.getEmail(),
                        requestMetadata,
                        "missing totp code during reauthentication");
                throw new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        "MFA_REQUIRED",
                        "Multi-factor authentication code is required.");
            }
            if (!mfaTotpService.isCodeValidForUser(currentUser, mfaCode)) {
                authAuditService.record(
                        AuthAuditEventType.STEP_UP_FAILURE,
                        currentUser,
                        currentUser.getEmail(),
                        requestMetadata,
                        "invalid totp code during reauthentication");
                throw invalidMfaCodeException();
            }
        }

        Instant reauthenticatedAt = Instant.now();
        userService.rotateSession(currentUser);
        refreshTokenService.revokeAllForUser(currentUser);
        authAuditService.record(
                AuthAuditEventType.STEP_UP_SUCCESS,
                currentUser,
                currentUser.getEmail(),
                requestMetadata,
                "reauthentication successful");
        return authenticate(currentUser, reauthenticatedAt);
    }

    public User me() {
        return currentUserService.getCurrentUser();
    }

    private AuthenticatedSession authenticate(User user) {
        return authenticate(user, null);
    }

    private AuthenticatedSession authenticate(User user, Instant reauthenticatedAt) {
        TokenService.AccessToken accessToken = tokenService.issueAccessToken(user, reauthenticatedAt);
        RefreshTokenService.RefreshSession refreshSession = refreshTokenService.issue(user);
        return new AuthenticatedSession(
                TOKEN_TYPE,
                accessToken.token(),
                accessToken.expiresAt(),
                refreshSession.token(),
                refreshSession.expiresAt(),
                user);
    }

    private void requireVerifiedEmail(User user) {
        if (!user.isEmailVerified()) {
            throw new ApiException(
                    HttpStatus.FORBIDDEN,
                    "EMAIL_NOT_VERIFIED",
                    "Email verification is required before continuing.");
        }
    }

    private void maybeUpgradePasswordHash(User user, String rawPassword) {
        if (user.getPasswordHash() != null && !user.getPasswordHash().startsWith("{pbkdf2}")) {
            userService.upgradePasswordHash(user, passwordEncoder.encode(rawPassword));
        }
    }

    private ApiException invalidLoginException() {
        return new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Invalid email or password.");
    }

    private ApiException invalidMfaCodeException() {
        return new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_MFA_CODE",
                "Invalid authentication code.");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private AuthenticatedSession loginWithFederatedProvider(
            FederatedAuthProvider provider,
            String idToken,
            String mfaCode,
            AuthRequestMetadata requestMetadata) {
        FederatedIdentity federatedIdentity = federatedIdentityVerifier.verifyLoginToken(provider, idToken);
        String normalizedEmail = userService.normalizeEmail(federatedIdentity.email());
        authAbuseProtectionService.assertLoginAllowed(requestMetadata.clientIp(), normalizedEmail);

        User user = resolveUserForFederatedIdentity(federatedIdentity);
        if (!user.isActive()) {
            authAbuseProtectionService.recordLoginFailure(requestMetadata.clientIp(), normalizedEmail);
            authAuditService.record(
                    AuthAuditEventType.LOGIN_FAILURE,
                    user,
                    normalizedEmail,
                    requestMetadata,
                    provider.name().toLowerCase(Locale.ROOT) + " login rejected because the account is disabled");
            throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "ACCOUNT_DISABLED",
                    "Account is no longer active.");
        }

        if (user.isTotpMfaEnabled()) {
            if (!hasText(mfaCode)) {
                throw new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        "MFA_REQUIRED",
                        "Multi-factor authentication code is required.");
            }
            if (!mfaTotpService.isCodeValidForUser(user, mfaCode)) {
                authAbuseProtectionService.recordLoginFailure(requestMetadata.clientIp(), normalizedEmail);
                authAuditService.record(
                        AuthAuditEventType.MFA_FAILURE,
                        user,
                        normalizedEmail,
                        requestMetadata,
                        "invalid totp code during " + provider.name().toLowerCase(Locale.ROOT) + " login");
                throw invalidMfaCodeException();
            }
        }

        if (federatedIdentity.emailVerified() && !user.isEmailVerified()) {
            userService.markEmailVerified(user, Instant.now());
        }
        externalIdentityService.link(user, federatedIdentity);
        authAbuseProtectionService.clearLoginFailures(requestMetadata.clientIp(), normalizedEmail);
        authAuditService.record(
                AuthAuditEventType.LOGIN_SUCCESS,
                user,
                normalizedEmail,
                requestMetadata,
                provider.name().toLowerCase(Locale.ROOT) + " login successful");
        return authenticate(userService.getRequiredUser(user.getId()), Instant.now());
    }

    private User resolveUserForFederatedIdentity(FederatedIdentity federatedIdentity) {
        return externalIdentityService.findUser(federatedIdentity.provider(), federatedIdentity.subject())
                .orElseGet(() -> userService.findByEmail(federatedIdentity.email())
                        .orElseGet(() -> userService.registerFederatedUser(
                                federatedIdentity.email(),
                                passwordEncoder.encode(generateFederatedPlaceholderPassword(federatedIdentity)),
                                fallbackFederatedFullName(federatedIdentity),
                                federatedIdentity.emailVerified() ? Instant.now() : null)));
    }

    private String fallbackFederatedFullName(FederatedIdentity federatedIdentity) {
        if (hasText(federatedIdentity.fullName())) {
            return federatedIdentity.fullName();
        }
        return federatedIdentity.email();
    }

    private String generateFederatedPlaceholderPassword(FederatedIdentity federatedIdentity) {
        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        return federatedIdentity.provider().name() + ":" + federatedIdentity.subject() + ":"
                + PLACEHOLDER_PASSWORD_ENCODER.encodeToString(randomBytes);
    }
}
