package com.authapi.core.modules.auth.api.controller;

import java.time.Duration;

import com.authapi.core.common.config.CoreApiPaths;
import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.modules.auth.application.account.AccountApplicationService;
import com.authapi.core.modules.auth.application.email.EmailVerificationApplicationService;
import com.authapi.core.modules.auth.application.mfa.TotpMfaApplicationService;
import com.authapi.core.modules.auth.application.password.PasswordApplicationService;
import com.authapi.core.modules.auth.application.session.AuthenticatedSession;
import com.authapi.core.modules.auth.api.dto.AuthResponse;
import com.authapi.core.modules.auth.api.dto.ChangePasswordRequest;
import com.authapi.core.modules.auth.api.dto.ChangeEmailRequest;
import com.authapi.core.modules.auth.api.dto.ConfirmTotpMfaRequest;
import com.authapi.core.modules.auth.api.dto.ConfirmEmailVerificationRequest;
import com.authapi.core.modules.auth.api.dto.DisableTotpMfaRequest;
import com.authapi.core.modules.auth.api.dto.EmailVerificationRequest;
import com.authapi.core.modules.auth.api.dto.FederatedLoginRequest;
import com.authapi.core.modules.auth.api.dto.ForgotPasswordRequest;
import com.authapi.core.modules.auth.api.dto.LoginRequest;
import com.authapi.core.modules.auth.api.dto.MeResponse;
import com.authapi.core.modules.auth.api.dto.ReauthenticateRequest;
import com.authapi.core.modules.auth.api.dto.RefreshRequest;
import com.authapi.core.modules.auth.api.dto.ResetPasswordRequest;
import com.authapi.core.modules.auth.api.dto.RegisterRequest;
import com.authapi.core.modules.auth.api.dto.SetupTotpMfaResponse;
import com.authapi.core.modules.auth.application.session.SessionApplicationService;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(CoreApiPaths.V1)
public class AuthController {

    private final SessionApplicationService sessionApplicationService;

    private final EmailVerificationApplicationService emailVerificationApplicationService;

    private final TotpMfaApplicationService totpMfaApplicationService;

    private final PasswordApplicationService passwordApplicationService;

    private final AccountApplicationService accountApplicationService;

    private final SecurityProperties securityProperties;

    public AuthController(
        SessionApplicationService sessionApplicationService,
        EmailVerificationApplicationService emailVerificationApplicationService,
        TotpMfaApplicationService totpMfaApplicationService,
        PasswordApplicationService passwordApplicationService,
        AccountApplicationService accountApplicationService,
        SecurityProperties securityProperties
    ) {
        this.sessionApplicationService = sessionApplicationService;
        this.emailVerificationApplicationService = emailVerificationApplicationService;
        this.totpMfaApplicationService = totpMfaApplicationService;
        this.passwordApplicationService = passwordApplicationService;
        this.accountApplicationService = accountApplicationService;
        this.securityProperties = securityProperties;
    }

    @PostMapping("/auth/register")
    public ResponseEntity<AuthResponse> register(
        @Valid @RequestBody RegisterRequest request,
        HttpServletResponse response
    ) {
        AuthenticatedSession session = sessionApplicationService.register(
            request.email(),
            request.password(),
            request.fullName()
        );
        AuthResponse authResponse = AuthResponse.from(session);
        writeRefreshCookie(response, authResponse.refreshToken(), authResponse.refreshTokenExpiresAt().toEpochMilli());
        return ResponseEntity.status(HttpStatus.CREATED).body(authResponse);
    }

    @PostMapping("/auth/login")
    public ResponseEntity<AuthResponse> login(
        @Valid @RequestBody LoginRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        AuthenticatedSession session = sessionApplicationService.login(
            request.email(),
            request.password(),
            request.mfaCode(),
            resolveRequestMetadata(servletRequest)
        );
        AuthResponse authResponse = AuthResponse.from(session);
        writeRefreshCookie(response, authResponse.refreshToken(), authResponse.refreshTokenExpiresAt().toEpochMilli());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/auth/login/google")
    public ResponseEntity<AuthResponse> loginWithGoogle(
        @Valid @RequestBody FederatedLoginRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        AuthResponse authResponse = AuthResponse.from(sessionApplicationService.loginWithGoogle(
            request.idToken(),
            request.mfaCode(),
            resolveRequestMetadata(servletRequest)
        ));
        writeRefreshCookie(response, authResponse.refreshToken(), authResponse.refreshTokenExpiresAt().toEpochMilli());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/auth/login/microsoft")
    public ResponseEntity<AuthResponse> loginWithMicrosoft(
        @Valid @RequestBody FederatedLoginRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        AuthResponse authResponse = AuthResponse.from(sessionApplicationService.loginWithMicrosoft(
            request.idToken(),
            request.mfaCode(),
            resolveRequestMetadata(servletRequest)
        ));
        writeRefreshCookie(response, authResponse.refreshToken(), authResponse.refreshTokenExpiresAt().toEpochMilli());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<AuthResponse> refresh(
        @RequestBody(required = false) RefreshRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        String refreshToken = resolveRefreshToken(request, servletRequest);
        AuthResponse authResponse = AuthResponse.from(
            sessionApplicationService.refresh(refreshToken, resolveRequestMetadata(servletRequest))
        );
        writeRefreshCookie(response, authResponse.refreshToken(), authResponse.refreshTokenExpiresAt().toEpochMilli());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(
        @RequestBody(required = false) RefreshRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        sessionApplicationService.logout(resolveRefreshToken(request, servletRequest), resolveRequestMetadata(servletRequest));
        clearRefreshCookie(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/reauthenticate")
    public ResponseEntity<AuthResponse> reauthenticate(
        @Valid @RequestBody ReauthenticateRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        AuthResponse authResponse = AuthResponse.from(sessionApplicationService.reauthenticate(
            request.password(),
            request.mfaCode(),
            resolveRequestMetadata(servletRequest)
        ));
        writeRefreshCookie(response, authResponse.refreshToken(), authResponse.refreshTokenExpiresAt().toEpochMilli());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/auth/mfa/totp/setup")
    public ResponseEntity<SetupTotpMfaResponse> beginTotpMfaSetup(HttpServletRequest servletRequest) {
        return ResponseEntity.ok(SetupTotpMfaResponse.from(
            totpMfaApplicationService.beginSetup(resolveRequestMetadata(servletRequest))
        ));
    }

    @PostMapping("/auth/mfa/totp/confirm")
    public ResponseEntity<Void> confirmTotpMfaSetup(
        @Valid @RequestBody ConfirmTotpMfaRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        totpMfaApplicationService.confirmSetup(request.code(), resolveRequestMetadata(servletRequest));
        clearRefreshCookie(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/mfa/totp/disable")
    public ResponseEntity<Void> disableTotpMfa(
        @Valid @RequestBody DisableTotpMfaRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        totpMfaApplicationService.disable(request.code(), resolveRequestMetadata(servletRequest));
        clearRefreshCookie(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/email-verification/request")
    public ResponseEntity<Void> requestEmailVerification(@Valid @RequestBody EmailVerificationRequest request) {
        emailVerificationApplicationService.requestVerification(request.email());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/auth/email-verification/confirm")
    public ResponseEntity<Void> confirmEmailVerification(
        @Valid @RequestBody ConfirmEmailVerificationRequest request
    ) {
        emailVerificationApplicationService.confirmVerification(request.token());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/change-password")
    public ResponseEntity<Void> changePassword(
        @Valid @RequestBody ChangePasswordRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        passwordApplicationService.changePassword(
            request.currentPassword(),
            request.newPassword(),
            resolveRequestMetadata(servletRequest)
        );
        clearRefreshCookie(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/change-email")
    public ResponseEntity<Void> changeEmail(
        @Valid @RequestBody ChangeEmailRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        accountApplicationService.changeEmail(request.newEmail(), resolveRequestMetadata(servletRequest));
        clearRefreshCookie(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/forgot-password")
    public ResponseEntity<Void> forgotPassword(
        @Valid @RequestBody ForgotPasswordRequest request,
        HttpServletRequest servletRequest
    ) {
        passwordApplicationService.forgotPassword(request.email(), resolveRequestMetadata(servletRequest));
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/auth/reset-password")
    public ResponseEntity<Void> resetPassword(
        @Valid @RequestBody ResetPasswordRequest request,
        HttpServletRequest servletRequest
    ) {
        passwordApplicationService.resetPassword(
            request.token(),
            request.newPassword(),
            resolveRequestMetadata(servletRequest)
        );
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/logout-all-sessions")
    public ResponseEntity<Void> logoutAllSessions(
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        accountApplicationService.logoutAllSessions(resolveRequestMetadata(servletRequest));
        clearRefreshCookie(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/auth/delete-account")
    public ResponseEntity<Void> deleteAccount(
        HttpServletRequest servletRequest,
        HttpServletResponse response
    ) {
        accountApplicationService.deleteAccount(resolveRequestMetadata(servletRequest));
        clearRefreshCookie(response);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public ResponseEntity<MeResponse> me() {
        return ResponseEntity.ok(MeResponse.from(sessionApplicationService.me()));
    }

    private String resolveRefreshToken(RefreshRequest request, HttpServletRequest servletRequest) {
        if (request != null && StringUtils.hasText(request.refreshToken())) {
            return request.refreshToken();
        }
        if (servletRequest.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : servletRequest.getCookies()) {
            if (securityProperties.getRefreshCookie().getName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private void writeRefreshCookie(HttpServletResponse response, String refreshToken, long expiresAtEpochMillis) {
        Duration maxAge = Duration.ofMillis(Math.max(0, expiresAtEpochMillis - System.currentTimeMillis()));
        ResponseCookie cookie = ResponseCookie.from(securityProperties.getRefreshCookie().getName(), refreshToken)
            .httpOnly(true)
            .secure(securityProperties.getRefreshCookie().isSecure())
            .sameSite(securityProperties.getRefreshCookie().getSameSite())
            .path(securityProperties.getRefreshCookie().getPath())
            .maxAge(maxAge)
            .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(securityProperties.getRefreshCookie().getName(), "")
            .httpOnly(true)
            .secure(securityProperties.getRefreshCookie().isSecure())
            .sameSite(securityProperties.getRefreshCookie().getSameSite())
            .path(securityProperties.getRefreshCookie().getPath())
            .maxAge(Duration.ZERO)
            .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private AuthRequestMetadata resolveRequestMetadata(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        String clientIp = StringUtils.hasText(forwardedFor)
            ? forwardedFor.split(",")[0].trim()
            : request.getRemoteAddr();
        String userAgent = request.getHeader(HttpHeaders.USER_AGENT);
        return new AuthRequestMetadata(
            StringUtils.hasText(clientIp) ? clientIp : "unknown",
            userAgent == null ? "" : userAgent
        );
    }
}
