package com.authapi.core.common.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "authapi.security")
public class SecurityProperties {

    private final Jwt jwt = new Jwt();

    private final Cors cors = new Cors();

    private final RefreshCookie refreshCookie = new RefreshCookie();

    private final EmailVerification emailVerification = new EmailVerification();

    private final PasswordReset passwordReset = new PasswordReset();

    private final MfaTotp mfaTotp = new MfaTotp();

    private final StepUp stepUp = new StepUp();

    private final RateLimit rateLimit = new RateLimit();

    private final Federation federation = new Federation();

    public Jwt getJwt() {
        return jwt;
    }

    public Cors getCors() {
        return cors;
    }

    public RefreshCookie getRefreshCookie() {
        return refreshCookie;
    }

    public EmailVerification getEmailVerification() {
        return emailVerification;
    }

    public PasswordReset getPasswordReset() {
        return passwordReset;
    }

    public MfaTotp getMfaTotp() {
        return mfaTotp;
    }

    public StepUp getStepUp() {
        return stepUp;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public Federation getFederation() {
        return federation;
    }

    public static final class Jwt {

        private String issuer = "authapi";

        private String secret = "dev-only-authapi-secret-change-me-please-143516989";

        private Duration accessTokenTtl = Duration.ofMinutes(15);

        private Duration refreshTokenTtl = Duration.ofDays(30);

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public Duration getAccessTokenTtl() {
            return accessTokenTtl;
        }

        public void setAccessTokenTtl(Duration accessTokenTtl) {
            this.accessTokenTtl = accessTokenTtl;
        }

        public Duration getRefreshTokenTtl() {
            return refreshTokenTtl;
        }

        public void setRefreshTokenTtl(Duration refreshTokenTtl) {
            this.refreshTokenTtl = refreshTokenTtl;
        }
    }

    public static final class Cors {

        private List<String> allowedOrigins = new ArrayList<>(List.of(
            "http://localhost:3000",
            "http://localhost:5173"
        ));

        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins == null ? new ArrayList<>() : new ArrayList<>(allowedOrigins);
        }
    }

    public static final class RefreshCookie {

        private String name = "authapi_refresh_token";

        private boolean secure;

        private String sameSite = "Lax";

        private String path = "/api/v1/auth";

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public boolean isSecure() {
            return secure;
        }

        public void setSecure(boolean secure) {
            this.secure = secure;
        }

        public String getSameSite() {
            return sameSite;
        }

        public void setSameSite(String sameSite) {
            this.sameSite = sameSite;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }
    }

    public static final class EmailVerification {

        private Duration tokenTtl = Duration.ofHours(24);

        private String verificationUrlTemplate = "http://localhost:8080/verify-email?token={token}";

        public Duration getTokenTtl() {
            return tokenTtl;
        }

        public void setTokenTtl(Duration tokenTtl) {
            this.tokenTtl = tokenTtl;
        }

        public String getVerificationUrlTemplate() {
            return verificationUrlTemplate;
        }

        public void setVerificationUrlTemplate(String verificationUrlTemplate) {
            this.verificationUrlTemplate = verificationUrlTemplate;
        }
    }

    public static final class PasswordReset {

        private Duration tokenTtl = Duration.ofHours(1);

        private String resetUrlTemplate = "http://localhost:8080/reset-password?token={token}";

        private Duration requestMinResponseTime = Duration.ofMillis(400);

        private Duration resetMinResponseTime = Duration.ofMillis(400);

        public Duration getTokenTtl() {
            return tokenTtl;
        }

        public void setTokenTtl(Duration tokenTtl) {
            this.tokenTtl = tokenTtl;
        }

        public String getResetUrlTemplate() {
            return resetUrlTemplate;
        }

        public void setResetUrlTemplate(String resetUrlTemplate) {
            this.resetUrlTemplate = resetUrlTemplate;
        }

        public Duration getRequestMinResponseTime() {
            return requestMinResponseTime;
        }

        public void setRequestMinResponseTime(Duration requestMinResponseTime) {
            this.requestMinResponseTime = requestMinResponseTime;
        }

        public Duration getResetMinResponseTime() {
            return resetMinResponseTime;
        }

        public void setResetMinResponseTime(Duration resetMinResponseTime) {
            this.resetMinResponseTime = resetMinResponseTime;
        }
    }

    public static final class StepUp {

        private Duration maxAge = Duration.ofMinutes(10);

        public Duration getMaxAge() {
            return maxAge;
        }

        public void setMaxAge(Duration maxAge) {
            this.maxAge = maxAge;
        }
    }

    public static final class MfaTotp {

        private String issuer = "AuthApi";

        private String encryptionSecret = "dev-only-authapi-totp-secret-change-me-123456789";

        private int digits = 6;

        private Duration period = Duration.ofSeconds(30);

        private int allowedDriftWindows = 1;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getEncryptionSecret() {
            return encryptionSecret;
        }

        public void setEncryptionSecret(String encryptionSecret) {
            this.encryptionSecret = encryptionSecret;
        }

        public int getDigits() {
            return digits;
        }

        public void setDigits(int digits) {
            this.digits = digits;
        }

        public Duration getPeriod() {
            return period;
        }

        public void setPeriod(Duration period) {
            this.period = period;
        }

        public int getAllowedDriftWindows() {
            return allowedDriftWindows;
        }

        public void setAllowedDriftWindows(int allowedDriftWindows) {
            this.allowedDriftWindows = allowedDriftWindows;
        }
    }

    public static final class RateLimit {

        private final RateLimitPolicy login = new RateLimitPolicy(5, Duration.ofMinutes(15), Duration.ofSeconds(30), Duration.ofMinutes(15));

        private final RateLimitPolicy forgotPassword =
            new RateLimitPolicy(3, Duration.ofMinutes(15), Duration.ofMinutes(1), Duration.ofMinutes(30));

        private final RateLimitPolicy resetPassword =
            new RateLimitPolicy(5, Duration.ofMinutes(15), Duration.ofSeconds(30), Duration.ofMinutes(15));

        public RateLimitPolicy getLogin() {
            return login;
        }

        public RateLimitPolicy getForgotPassword() {
            return forgotPassword;
        }

        public RateLimitPolicy getResetPassword() {
            return resetPassword;
        }
    }

    public static final class RateLimitPolicy {

        private int threshold;

        private Duration trackingWindow;

        private Duration baseBlockDuration;

        private Duration maxBlockDuration;

        public RateLimitPolicy() {
        }

        public RateLimitPolicy(
            int threshold,
            Duration trackingWindow,
            Duration baseBlockDuration,
            Duration maxBlockDuration
        ) {
            this.threshold = threshold;
            this.trackingWindow = trackingWindow;
            this.baseBlockDuration = baseBlockDuration;
            this.maxBlockDuration = maxBlockDuration;
        }

        public int getThreshold() {
            return threshold;
        }

        public void setThreshold(int threshold) {
            this.threshold = threshold;
        }

        public Duration getTrackingWindow() {
            return trackingWindow;
        }

        public void setTrackingWindow(Duration trackingWindow) {
            this.trackingWindow = trackingWindow;
        }

        public Duration getBaseBlockDuration() {
            return baseBlockDuration;
        }

        public void setBaseBlockDuration(Duration baseBlockDuration) {
            this.baseBlockDuration = baseBlockDuration;
        }

        public Duration getMaxBlockDuration() {
            return maxBlockDuration;
        }

        public void setMaxBlockDuration(Duration maxBlockDuration) {
            this.maxBlockDuration = maxBlockDuration;
        }
    }

    public static final class Federation {

        private final Google google = new Google();

        private final Microsoft microsoft = new Microsoft();

        public Google getGoogle() {
            return google;
        }

        public Microsoft getMicrosoft() {
            return microsoft;
        }
    }

    public static class OidcProvider {

        private String clientId = "";

        private String jwkSetUri = "";

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getJwkSetUri() {
            return jwkSetUri;
        }

        public void setJwkSetUri(String jwkSetUri) {
            this.jwkSetUri = jwkSetUri;
        }
    }

    public static final class Google extends OidcProvider {

        private String issuer = "https://accounts.google.com";

        public Google() {
            setJwkSetUri("https://www.googleapis.com/oauth2/v3/certs");
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }
    }

    public static final class Microsoft extends OidcProvider {

        private List<String> acceptedIssuerPrefixes = new ArrayList<>(List.of(
            "https://login.microsoftonline.com/",
            "https://sts.windows.net/"
        ));

        public Microsoft() {
            setJwkSetUri("https://login.microsoftonline.com/common/discovery/v2.0/keys");
        }

        public List<String> getAcceptedIssuerPrefixes() {
            return acceptedIssuerPrefixes;
        }

        public void setAcceptedIssuerPrefixes(List<String> acceptedIssuerPrefixes) {
            this.acceptedIssuerPrefixes = acceptedIssuerPrefixes == null
                ? new ArrayList<>()
                : new ArrayList<>(acceptedIssuerPrefixes);
        }
    }
}
