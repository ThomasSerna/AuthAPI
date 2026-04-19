package com.authapi.core.modules.auth.domain.service;

import java.time.Instant;
import java.util.List;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.modules.user.domain.model.User;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;

    private final SecurityProperties securityProperties;

    public TokenService(JwtEncoder jwtEncoder, SecurityProperties securityProperties) {
        this.jwtEncoder = jwtEncoder;
        this.securityProperties = securityProperties;
    }

    public AccessToken issueAccessToken(User user) {
        return issueAccessToken(user, null);
    }

    public AccessToken issueAccessToken(User user, Instant reauthenticatedAt) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(securityProperties.getJwt().getAccessTokenTtl());
        List<String> roles = user.getRoles().stream()
            .map(role -> role.getName())
            .sorted()
            .toList();
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
            .issuer(securityProperties.getJwt().getIssuer())
            .issuedAt(issuedAt)
            .expiresAt(expiresAt)
            .subject(user.getId().toString())
            .claim("email", user.getEmail())
            .claim("fullName", user.getFullName())
            .claim("roles", roles)
            .claim("pwdChangedAt", user.getPasswordChangedAt().toEpochMilli())
            .claim("sessionVersion", user.getSessionVersion());
        if (reauthenticatedAt != null) {
            claimsBuilder.claim("reauthenticatedAt", reauthenticatedAt.toEpochMilli());
        }
        JwtClaimsSet claims = claimsBuilder.build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String tokenValue = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new AccessToken(tokenValue, expiresAt);
    }

    public record AccessToken(String token, Instant expiresAt) {
    }
}
