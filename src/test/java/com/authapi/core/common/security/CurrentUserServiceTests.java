package com.authapi.core.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.model.UserStatus;
import com.authapi.core.modules.user.domain.service.UserService;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

class CurrentUserServiceTests {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getCurrentUserShouldAcceptPasswordChangedAtClaimWithinSameSecond() {
        UserService userService = mock(UserService.class);
        CurrentUserService currentUserService = new CurrentUserService(userService, new SecurityProperties());
        User user = buildUser(Instant.parse("2026-04-08T22:35:06Z"), 0);

        when(userService.getRequiredUser(user.getId())).thenReturn(user);

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwtForUser(
            user,
            user.getPasswordChangedAt().plusMillis(987).toEpochMilli(),
            user.getSessionVersion()
        )));

        assertThat(currentUserService.getCurrentUser()).isSameAs(user);
    }

    @Test
    void getCurrentUserShouldRejectPasswordChangedAtClaimFromDifferentSecond() {
        UserService userService = mock(UserService.class);
        CurrentUserService currentUserService = new CurrentUserService(userService, new SecurityProperties());
        User user = buildUser(Instant.parse("2026-04-08T22:35:06Z"), 0);

        when(userService.getRequiredUser(user.getId())).thenReturn(user);

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwtForUser(
            user,
            user.getPasswordChangedAt().minusSeconds(1).toEpochMilli(),
            user.getSessionVersion()
        )));

        assertThatThrownBy(currentUserService::getCurrentUser)
            .isInstanceOf(ApiException.class)
            .extracting("code")
            .isEqualTo("STALE_ACCESS_TOKEN");
    }

    private User buildUser(Instant passwordChangedAt, int sessionVersion) {
        User user = new User();
        setId(user, UUID.randomUUID());
        user.setEmail("debug@example.com");
        user.setStatus(UserStatus.ACTIVE);
        user.setPasswordChangedAt(passwordChangedAt);
        user.setSessionVersion(sessionVersion);
        return user;
    }

    private void setId(User user, UUID id) {
        try {
            Field idField = User.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(user, id);
        } catch (ReflectiveOperationException exception) {
            throw new IllegalStateException("Unable to assign a test user id.", exception);
        }
    }

    private Jwt jwtForUser(User user, long passwordChangedAtClaim, int sessionVersion) {
        Instant issuedAt = Instant.parse("2026-04-08T22:35:10Z");
        return new Jwt(
            "token",
            issuedAt,
            issuedAt.plusSeconds(900),
            Map.of("alg", "HS256"),
            Map.of(
                "sub", user.getId().toString(),
                "pwdChangedAt", passwordChangedAtClaim,
                "sessionVersion", sessionVersion
            )
        );
    }
}
