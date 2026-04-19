package com.authapi.core.modules.auth.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Map;

import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.auth.domain.service.OidcFederatedIdentityVerifier;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;
import com.authapi.core.modules.auth.domain.support.FederatedIdentity;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class OidcFederatedIdentityVerifierTests {

    @Test
    void googleIdentityShouldRequireVerifiedEmail() {
        OidcFederatedIdentityVerifier verifier = new OidcFederatedIdentityVerifier(Map.of(
            FederatedAuthProvider.GOOGLE,
            ignored -> jwt(Map.of(
                "sub", "google-subject",
                "email", "student@example.com",
                "email_verified", false
            ), "https://accounts.google.com")
        ));

        assertThatThrownBy(() -> verifier.verifyLoginToken(FederatedAuthProvider.GOOGLE, "token"))
            .isInstanceOf(ApiException.class)
            .extracting("code")
            .isEqualTo("INVALID_FEDERATED_TOKEN");
    }

    @Test
    void microsoftIdentityShouldUsePreferredUsernameForUniversityAccounts() {
        OidcFederatedIdentityVerifier verifier = new OidcFederatedIdentityVerifier(Map.of(
            FederatedAuthProvider.MICROSOFT,
            ignored -> jwt(Map.of(
                "sub", "microsoft-subject",
                "preferred_username", "student@university.edu",
                "name", "University Student"
            ), "https://login.microsoftonline.com/tenant-id/v2.0")
        ));

        FederatedIdentity identity = verifier.verifyLoginToken(FederatedAuthProvider.MICROSOFT, "token");

        assertThat(identity.email()).isEqualTo("student@university.edu");
        assertThat(identity.fullName()).isEqualTo("University Student");
        assertThat(identity.emailVerified()).isTrue();
    }

    @Test
    void providerWithoutDecoderShouldBeReportedAsDisabled() {
        OidcFederatedIdentityVerifier verifier = new OidcFederatedIdentityVerifier(Map.of());

        assertThatThrownBy(() -> verifier.verifyLoginToken(FederatedAuthProvider.MICROSOFT, "token"))
            .isInstanceOf(ApiException.class)
            .extracting("code")
            .isEqualTo("FEDERATED_PROVIDER_DISABLED");
    }

    private Jwt jwt(Map<String, Object> claims, String issuer) {
        Instant issuedAt = Instant.parse("2026-04-08T22:00:00Z");
        Map<String, Object> jwtClaims = new java.util.LinkedHashMap<>(claims);
        jwtClaims.put("iss", issuer);
        return new Jwt(
            "token",
            issuedAt,
            issuedAt.plusSeconds(900),
            Map.of("alg", "RS256"),
            jwtClaims
        );
    }
}
