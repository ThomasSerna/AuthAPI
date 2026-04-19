package com.authapi.core.modules.auth.domain.support;

public record AuthRequestMetadata(String clientIp, String userAgent) {

    public static AuthRequestMetadata empty() {
        return new AuthRequestMetadata("unknown", "");
    }
}
