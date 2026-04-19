package com.authapi.core.common.security;

import java.time.Instant;
import java.util.UUID;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.service.UserService;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class CurrentUserService {

    private final UserService userService;

    private final SecurityProperties securityProperties;

    public CurrentUserService(UserService userService, SecurityProperties securityProperties) {
        this.userService = userService;
        this.securityProperties = securityProperties;
    }

    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication required.");
        }
        try {
            UUID userId = UUID.fromString(authentication.getName());
            User user = userService.getRequiredUser(userId);
            if (!user.isActive()) {
                throw new ApiException(
                    HttpStatus.UNAUTHORIZED,
                    "ACCOUNT_DISABLED",
                    "Account is no longer active."
                );
            }
            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                Object passwordChangedAtClaim = jwtAuthenticationToken.getToken().getClaims().get("pwdChangedAt");
                if (passwordChangedAtClaim instanceof Number passwordChangedAtNumber
                    && !matchesPersistedInstant(passwordChangedAtNumber.longValue(), user.getPasswordChangedAt())) {
                    throw new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        "STALE_ACCESS_TOKEN",
                        "Access token is no longer valid."
                    );
                }
                Object sessionVersionClaim = jwtAuthenticationToken.getToken().getClaims().get("sessionVersion");
                long tokenSessionVersion = sessionVersionClaim instanceof Number sessionVersionNumber
                    ? sessionVersionNumber.longValue()
                    : 0L;
                if (tokenSessionVersion != user.getSessionVersion()) {
                    throw new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        "STALE_ACCESS_TOKEN",
                        "Access token is no longer valid."
                    );
                }
            }
            return user;
        } catch (IllegalArgumentException exception) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_ACCESS_TOKEN", "Invalid access token.");
        }
    }

    public User getCurrentUserRequiringRecentReauthentication() {
        User user = getCurrentUser();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            Object reauthenticatedAtClaim = jwtAuthenticationToken.getToken().getClaims().get("reauthenticatedAt");
            if (reauthenticatedAtClaim instanceof Number reauthenticatedAtNumber) {
                Instant reauthenticatedAt = Instant.ofEpochMilli(reauthenticatedAtNumber.longValue());
                if (!reauthenticatedAt.plus(securityProperties.getStepUp().getMaxAge()).isBefore(Instant.now())) {
                    return user;
                }
            }
        }
        throw new ApiException(
            HttpStatus.FORBIDDEN,
            "REAUTHENTICATION_REQUIRED",
            "Recent reauthentication is required."
        );
    }

    private boolean matchesPersistedInstant(long claimedEpochMillis, Instant persistedInstant) {
        return claimedEpochMillis / 1000 == persistedInstant.toEpochMilli() / 1000;
    }
}
