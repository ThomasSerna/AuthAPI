package com.authapi.core.modules.auth.domain.service;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;
import com.authapi.core.modules.auth.domain.support.FederatedIdentity;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.StringUtils;

public class OidcFederatedIdentityVerifier implements FederatedIdentityVerifier {

    private final Map<FederatedAuthProvider, JwtDecoder> decoders;

    public OidcFederatedIdentityVerifier(Map<FederatedAuthProvider, JwtDecoder> decoders) {
        this.decoders = new EnumMap<>(FederatedAuthProvider.class);
        this.decoders.putAll(Objects.requireNonNull(decoders));
    }

    @Override
    public FederatedIdentity verifyLoginToken(FederatedAuthProvider provider, String idToken) {
        JwtDecoder jwtDecoder = decoders.get(provider);
        if (jwtDecoder == null) {
            throw new ApiException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "FEDERATED_PROVIDER_DISABLED",
                providerName(provider) + " login is not configured."
            );
        }

        try {
            Jwt jwt = jwtDecoder.decode(idToken);
            return switch (provider) {
                case GOOGLE -> googleIdentity(jwt);
                case MICROSOFT -> microsoftIdentity(jwt);
            };
        } catch (JwtException exception) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_FEDERATED_TOKEN",
                "Invalid " + providerName(provider) + " ID token."
            );
        }
    }

    private FederatedIdentity googleIdentity(Jwt jwt) {
        String email = requiredEmail(firstText(jwt, "email"), FederatedAuthProvider.GOOGLE);
        boolean emailVerified = Boolean.TRUE.equals(jwt.getClaim("email_verified"));
        if (!emailVerified) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_FEDERATED_TOKEN",
                "Google account email must be verified."
            );
        }

        return new FederatedIdentity(
            FederatedAuthProvider.GOOGLE,
            requiredSubject(jwt, FederatedAuthProvider.GOOGLE),
            email,
            fallbackDisplayName(jwt, email),
            true,
            jwt.getIssuer() == null ? "" : jwt.getIssuer().toString()
        );
    }

    private FederatedIdentity microsoftIdentity(Jwt jwt) {
        String email = requiredEmail(
            firstText(jwt, "email", "preferred_username", "upn", "unique_name"),
            FederatedAuthProvider.MICROSOFT
        );
        boolean emailVerified = jwt.getClaims().containsKey("email_verified")
            ? Boolean.TRUE.equals(jwt.getClaim("email_verified"))
            : true;

        return new FederatedIdentity(
            FederatedAuthProvider.MICROSOFT,
            requiredSubject(jwt, FederatedAuthProvider.MICROSOFT),
            email,
            fallbackDisplayName(jwt, email),
            emailVerified,
            jwt.getIssuer() == null ? "" : jwt.getIssuer().toString()
        );
    }

    private String requiredSubject(Jwt jwt, FederatedAuthProvider provider) {
        if (!StringUtils.hasText(jwt.getSubject())) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_FEDERATED_TOKEN",
                providerName(provider) + " ID token must include a subject."
            );
        }
        return jwt.getSubject();
    }

    private String requiredEmail(String email, FederatedAuthProvider provider) {
        if (!StringUtils.hasText(email) || !email.contains("@")) {
            throw new ApiException(
                HttpStatus.BAD_REQUEST,
                "FEDERATED_EMAIL_REQUIRED",
                providerName(provider) + " login requires an email address."
            );
        }
        return email.trim();
    }

    private String fallbackDisplayName(Jwt jwt, String email) {
        String name = firstText(jwt, "name");
        if (StringUtils.hasText(name)) {
            return name.trim();
        }
        String givenName = firstText(jwt, "given_name");
        String familyName = firstText(jwt, "family_name");
        String combinedName = (givenName + " " + familyName).trim();
        if (StringUtils.hasText(combinedName)) {
            return combinedName;
        }
        return email;
    }

    private String firstText(Jwt jwt, String... claimNames) {
        for (String claimName : claimNames) {
            Object claimValue = jwt.getClaims().get(claimName);
            if (claimValue instanceof String stringValue && StringUtils.hasText(stringValue)) {
                return stringValue.trim();
            }
        }
        return null;
    }

    private String providerName(FederatedAuthProvider provider) {
        return switch (provider) {
            case GOOGLE -> "Google";
            case MICROSOFT -> "Microsoft";
        };
    }
}
