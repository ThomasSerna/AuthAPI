package com.authapi.core.modules.auth.domain.model;

public record TotpSetup(
    String secret,
    String otpauthUrl,
    String issuer,
    String accountName
) {
}
