package com.authapi.core.modules.auth.config;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.modules.auth.domain.service.FederatedIdentityVerifier;
import com.authapi.core.modules.auth.domain.service.OidcFederatedIdentityVerifier;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.util.StringUtils;

@Configuration
public class FederatedIdentityConfig {

    @Bean
    public FederatedIdentityVerifier federatedIdentityVerifier(Map<FederatedAuthProvider, JwtDecoder> federatedJwtDecoders) {
        return new OidcFederatedIdentityVerifier(federatedJwtDecoders);
    }

    @Bean
    public Map<FederatedAuthProvider, JwtDecoder> federatedJwtDecoders(SecurityProperties securityProperties) {
        Map<FederatedAuthProvider, JwtDecoder> decoders = new EnumMap<>(FederatedAuthProvider.class);

        SecurityProperties.Google google = securityProperties.getFederation().getGoogle();
        if (isConfigured(google)) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(google.getJwkSetUri()).build();
            decoder.setJwtValidator(allOf(
                JwtValidators.createDefaultWithIssuer(google.getIssuer()),
                audienceValidator(google.getClientId())
            ));
            decoders.put(FederatedAuthProvider.GOOGLE, decoder);
        }

        SecurityProperties.Microsoft microsoft = securityProperties.getFederation().getMicrosoft();
        if (isConfigured(microsoft)) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(microsoft.getJwkSetUri()).build();
            decoder.setJwtValidator(allOf(
                new JwtTimestampValidator(),
                audienceValidator(microsoft.getClientId()),
                issuerPrefixValidator(microsoft.getAcceptedIssuerPrefixes())
            ));
            decoders.put(FederatedAuthProvider.MICROSOFT, decoder);
        }

        return decoders;
    }

    private boolean isConfigured(SecurityProperties.OidcProvider provider) {
        return StringUtils.hasText(provider.getClientId()) && StringUtils.hasText(provider.getJwkSetUri());
    }

    @SafeVarargs
    private final OAuth2TokenValidator<Jwt> allOf(OAuth2TokenValidator<Jwt>... validators) {
        return token -> {
            for (OAuth2TokenValidator<Jwt> validator : validators) {
                OAuth2TokenValidatorResult result = validator.validate(token);
                if (result.hasErrors()) {
                    return result;
                }
            }
            return OAuth2TokenValidatorResult.success();
        };
    }

    private OAuth2TokenValidator<Jwt> audienceValidator(String clientId) {
        return jwt -> jwt.getAudience().contains(clientId)
            ? OAuth2TokenValidatorResult.success()
            : OAuth2TokenValidatorResult.failure(new OAuth2Error(
                "invalid_token",
                "The required audience is missing.",
                null
            ));
    }

    private OAuth2TokenValidator<Jwt> issuerPrefixValidator(List<String> acceptedIssuerPrefixes) {
        return jwt -> {
            String issuer = jwt.getIssuer() == null ? "" : jwt.getIssuer().toString();
            boolean accepted = acceptedIssuerPrefixes.stream()
                .filter(StringUtils::hasText)
                .anyMatch(issuer::startsWith);
            return accepted
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "Issuer is not allowed for Microsoft sign-in.",
                    null
                ));
        };
    }
}
