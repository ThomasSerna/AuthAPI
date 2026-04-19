package com.authapi.core.modules.auth.application.account;

import com.authapi.core.common.security.CurrentUserService;
import com.authapi.core.modules.auth.domain.service.AuthAuditService;
import com.authapi.core.modules.auth.domain.service.EmailVerificationService;
import com.authapi.core.modules.auth.domain.service.RefreshTokenService;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.service.UserService;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class AccountApplicationService {

    private final CurrentUserService currentUserService;

    private final UserService userService;

    private final RefreshTokenService refreshTokenService;

    private final EmailVerificationService emailVerificationService;

    private final AuthAuditService authAuditService;

    public AccountApplicationService(
        CurrentUserService currentUserService,
        UserService userService,
        RefreshTokenService refreshTokenService,
        EmailVerificationService emailVerificationService,
        AuthAuditService authAuditService
    ) {
        this.currentUserService = currentUserService;
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.emailVerificationService = emailVerificationService;
        this.authAuditService = authAuditService;
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void changeEmail(String newEmail, AuthRequestMetadata requestMetadata) {
        User currentUser = currentUserService.getCurrentUserRequiringRecentReauthentication();
        String previousEmail = currentUser.getEmail();
        userService.changeEmail(currentUser, newEmail);
        refreshTokenService.revokeAllForUser(currentUser);
        emailVerificationService.sendVerificationFor(currentUser);
        authAuditService.record(
            AuthAuditEventType.EMAIL_CHANGE,
            currentUser,
            previousEmail,
            requestMetadata,
            "email changed and verification required"
        );
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void logoutAllSessions(AuthRequestMetadata requestMetadata) {
        User currentUser = currentUserService.getCurrentUserRequiringRecentReauthentication();
        userService.rotateSession(currentUser);
        refreshTokenService.revokeAllForUser(currentUser);
        authAuditService.record(
            AuthAuditEventType.LOGOUT_ALL_SESSIONS,
            currentUser,
            currentUser.getEmail(),
            requestMetadata,
            "all sessions logged out"
        );
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void deleteAccount(AuthRequestMetadata requestMetadata) {
        User currentUser = currentUserService.getCurrentUserRequiringRecentReauthentication();
        String previousEmail = currentUser.getEmail();
        userService.disableAccount(currentUser);
        refreshTokenService.revokeAllForUser(currentUser);
        authAuditService.record(
            AuthAuditEventType.ACCOUNT_DELETED,
            currentUser,
            previousEmail,
            requestMetadata,
            "account deleted"
        );
    }
}
