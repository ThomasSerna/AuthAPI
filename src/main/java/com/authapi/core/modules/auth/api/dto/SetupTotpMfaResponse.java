package com.authapi.core.modules.auth.api.dto;

import com.authapi.core.modules.auth.domain.model.TotpSetup;

public record SetupTotpMfaResponse(
    String secret,
    String otpauthUrl,
    String issuer,
    String accountName
) {

    public static SetupTotpMfaResponse from(TotpSetup setup) {
        return new SetupTotpMfaResponse(
            setup.secret(),
            setup.otpauthUrl(),
            setup.issuer(),
            setup.accountName()
        );
    }
}
