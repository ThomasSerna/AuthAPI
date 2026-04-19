package com.authapi.core.modules.auth.domain.support;

public record FederatedIdentity(
    FederatedAuthProvider provider,
    String subject,
    String email,
    String fullName,
    boolean emailVerified,
    String issuer
) {
}
