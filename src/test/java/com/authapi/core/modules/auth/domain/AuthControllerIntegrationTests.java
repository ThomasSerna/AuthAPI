package com.authapi.core.modules.auth.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.authapi.core.common.config.CoreApiPaths;
import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.auth.domain.port.PasswordResetEmailSender;
import com.authapi.core.modules.auth.domain.port.VerificationEmailSender;
import com.authapi.core.modules.auth.domain.service.FederatedIdentityVerifier;
import com.authapi.core.modules.auth.domain.service.MfaTotpService;
import com.authapi.core.modules.auth.domain.service.RefreshTokenService;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;
import com.authapi.core.modules.auth.domain.support.FederatedIdentity;
import com.authapi.core.modules.auth.infrastructure.persistence.JpaAuthAuditEventRepository;
import com.authapi.core.modules.auth.infrastructure.persistence.JpaEmailVerificationTokenRepository;
import com.authapi.core.modules.auth.infrastructure.persistence.JpaExternalIdentityRepository;
import com.authapi.core.modules.auth.infrastructure.persistence.JpaPasswordResetTokenRepository;
import com.authapi.core.modules.auth.infrastructure.persistence.JpaRefreshTokenRepository;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.infrastructure.persistence.JpaUserRepository;
import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIntegrationTests {

    @TestConfiguration
    static class TestConfig {

        @Bean
        @Primary
        CapturingVerificationEmailSender capturingVerificationEmailSender() {
            return new CapturingVerificationEmailSender();
        }

        @Bean
        @Primary
        CapturingPasswordResetEmailSender capturingPasswordResetEmailSender() {
            return new CapturingPasswordResetEmailSender();
        }

        @Bean
        @Primary
        StubFederatedIdentityVerifier stubFederatedIdentityVerifier() {
            return new StubFederatedIdentityVerifier();
        }
    }

    static class CapturingVerificationEmailSender implements VerificationEmailSender {

        private final java.util.concurrent.ConcurrentMap<String, String> tokensByEmail =
            new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public void sendEmailVerification(User user, String rawToken, Instant expiresAt) {
            tokensByEmail.put(user.getEmail(), rawToken);
        }

        void reset() {
            tokensByEmail.clear();
        }

        String tokenFor(String email) {
            return tokensByEmail.get(email);
        }
    }

    static class CapturingPasswordResetEmailSender implements PasswordResetEmailSender {

        private final java.util.concurrent.ConcurrentMap<String, String> urlsByEmail =
            new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public void sendPasswordReset(User user, String resetUrl, Instant expiresAt) {
            urlsByEmail.put(user.getEmail(), resetUrl);
        }

        void reset() {
            urlsByEmail.clear();
        }

        String urlFor(String email) {
            return urlsByEmail.get(email);
        }

        String tokenFor(String email) {
            String resetUrl = urlsByEmail.get(email);
            if (resetUrl == null) {
                return null;
            }

            int tokenStart = resetUrl.indexOf("token=");
            if (tokenStart < 0) {
                return null;
            }

            int valueStart = tokenStart + "token=".length();
            int valueEnd = resetUrl.indexOf('&', valueStart);
            String encodedToken = valueEnd >= 0
                ? resetUrl.substring(valueStart, valueEnd)
                : resetUrl.substring(valueStart);
            return URLDecoder.decode(encodedToken, StandardCharsets.UTF_8);
        }
    }

    static class StubFederatedIdentityVerifier implements FederatedIdentityVerifier {

        private final java.util.concurrent.ConcurrentMap<String, FederatedIdentity> identitiesByKey =
            new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public FederatedIdentity verifyLoginToken(FederatedAuthProvider provider, String idToken) {
            FederatedIdentity identity = identitiesByKey.get(key(provider, idToken));
            if (identity == null) {
                throw new ApiException(
                    org.springframework.http.HttpStatus.UNAUTHORIZED,
                    "INVALID_FEDERATED_TOKEN",
                    "Invalid " + provider.name().toLowerCase() + " ID token."
                );
            }
            return identity;
        }

        void stub(FederatedIdentity identity, String idToken) {
            identitiesByKey.put(key(identity.provider(), idToken), identity);
        }

        void reset() {
            identitiesByKey.clear();
        }

        private String key(FederatedAuthProvider provider, String idToken) {
            return provider.name() + "::" + idToken;
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JpaUserRepository userRepository;

    @Autowired
    private JpaRefreshTokenRepository refreshTokenRepository;

    @Autowired
    private JpaEmailVerificationTokenRepository emailVerificationTokenRepository;

    @Autowired
    private JpaExternalIdentityRepository externalIdentityRepository;

    @Autowired
    private JpaPasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private JpaAuthAuditEventRepository authAuditEventRepository;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private MfaTotpService mfaTotpService;

    @Autowired
    private CapturingVerificationEmailSender verificationEmailSender;

    @Autowired
    private CapturingPasswordResetEmailSender passwordResetEmailSender;

    @Autowired
    private StubFederatedIdentityVerifier federatedIdentityVerifier;

    @BeforeEach
    void cleanDatabase() {
        externalIdentityRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        emailVerificationTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        authAuditEventRepository.deleteAll();
        userRepository.deleteAll();
        verificationEmailSender.reset();
        passwordResetEmailSender.reset();
        federatedIdentityVerifier.reset();
    }

    @Test
    void registerShouldCreateUserIssueTokensAndExposeCurrentUser() throws Exception {
        AuthPayload authPayload = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");

        mockMvc.perform(get(CoreApiPaths.ME)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + authPayload.accessToken()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("thomas@example.com"))
            .andExpect(jsonPath("$.fullName").value("Thomas Serna"))
            .andExpect(jsonPath("$.roles", hasItem("USER")))
            .andExpect(jsonPath("$.emailVerified").value(false))
            .andExpect(jsonPath("$.totpMfaEnabled").value(false));

        assertThat(verificationEmailSender.tokenFor("thomas@example.com")).isNotBlank();
    }

    @Test
    void rootShouldServeIndexHtmlWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.CONTENT_TYPE, containsString("text/html")))
            .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains("<title>AuthApi</title>"));
    }

    @Test
    void googleFederatedLoginShouldProvisionVerifiedUserAndAllowTotpSetup() throws Exception {
        federatedIdentityVerifier.stub(new FederatedIdentity(
            FederatedAuthProvider.GOOGLE,
            "google-subject-1",
            "google.student@example.com",
            "Google Student",
            true,
            "https://accounts.google.com"
        ), "google-token");

        MvcResult loginResult = mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN_GOOGLE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.61")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("idToken", "google-token"))))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("authapi_refresh_token=")))
            .andExpect(jsonPath("$.user.email").value("google.student@example.com"))
            .andExpect(jsonPath("$.user.emailVerified").value(true))
            .andReturn();

        String accessToken = readAuthPayload(loginResult).accessToken();

        mockMvc.perform(post(CoreApiPaths.AUTH_MFA_TOTP_SETUP)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header("X-Forwarded-For", "198.51.100.61")
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.secret").isNotEmpty());

        User user = userRepository.findByEmailIgnoreCase("google.student@example.com").orElseThrow();
        assertThat(user.isEmailVerified()).isTrue();
        assertThat(externalIdentityRepository.findByProviderAndSubject(FederatedAuthProvider.GOOGLE, "google-subject-1"))
            .isPresent();
    }

    @Test
    void googleFederatedLoginShouldAcceptCredentialAlias() throws Exception {
        federatedIdentityVerifier.stub(new FederatedIdentity(
            FederatedAuthProvider.GOOGLE,
            "google-subject-alias",
            "alias.student@example.com",
            "Alias Student",
            true,
            "https://accounts.google.com"
        ), "google-credential");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN_GOOGLE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.63")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("credential", "google-credential"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.email").value("alias.student@example.com"))
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("authapi_refresh_token=")));
    }

    @Test
    void microsoftFederatedLoginShouldLinkUniversityAccountsToExistingUsers() throws Exception {
        registerUser("student@university.edu", "Prep3tud!2026", "Student Local");
        federatedIdentityVerifier.stub(new FederatedIdentity(
            FederatedAuthProvider.MICROSOFT,
            "microsoft-tenant-subject",
            "student@university.edu",
            "Student University",
            true,
            "https://login.microsoftonline.com/contoso-tenant/v2.0"
        ), "microsoft-token");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN_MICROSOFT)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.62")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("idToken", "microsoft-token"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.email").value("student@university.edu"))
            .andExpect(jsonPath("$.user.emailVerified").value(true));

        User user = userRepository.findByEmailIgnoreCase("student@university.edu").orElseThrow();
        assertThat(user.isEmailVerified()).isTrue();
        assertThat(externalIdentityRepository.findByProviderAndSubject(
            FederatedAuthProvider.MICROSOFT,
            "microsoft-tenant-subject"
        )).isPresent();
    }

    @Test
    void totpMfaShouldBeOptionalUntilExplicitlyEnabledAndThenRequiredForLogin() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.18")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.totpMfaEnabled").value(false));

        AuthPayload reauthenticatedAuth = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", null, "198.51.100.18");

        MvcResult setupResult = mockMvc.perform(post(CoreApiPaths.AUTH_MFA_TOTP_SETUP)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.18")
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.secret").isNotEmpty())
            .andExpect(jsonPath("$.otpauthUrl", containsString("otpauth://totp/")))
            .andReturn();

        String secret = objectMapper.readTree(setupResult.getResponse().getContentAsByteArray()).get("secret").asText();
        String totpCode = mfaTotpService.generateCodeForSecret(secret, Instant.now());

        mockMvc.perform(post(CoreApiPaths.AUTH_MFA_TOTP_CONFIRM)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.18")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of("code", totpCode))))
            .andExpect(status().isNoContent())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.18")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("MFA_REQUIRED"));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.18")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026",
                    "mfaCode", "000000"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_MFA_CODE"));

        String loginTotpCode = mfaTotpService.generateCodeForSecret(secret, Instant.now());
        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.18")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026",
                    "mfaCode", loginTotpCode
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.totpMfaEnabled").value(true));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.MFA_TOTP_SETUP_INITIATED)).isEqualTo(1);
        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.MFA_TOTP_ENABLED)).isEqualTo(1);
        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.MFA_FAILURE)).isEqualTo(1);
    }

    @Test
    void reauthenticateAndDisableTotpShouldRequireTotpWhenMfaIsEnabled() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        AuthPayload setupSession = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", null, "198.51.100.19");
        String secret = beginTotpSetup(setupSession.accessToken(), "198.51.100.19");
        confirmTotpSetup(setupSession.accessToken(), secret, "198.51.100.19");

        AuthPayload mfaLogin = loginWithTotp("thomas@example.com", "Prep3tud!2026", secret, "198.51.100.19");

        mockMvc.perform(post(CoreApiPaths.AUTH_REAUTHENTICATE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mfaLogin.accessToken())
                .header("X-Forwarded-For", "198.51.100.19")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of("password", "Prep3tud!2026"))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("MFA_REQUIRED"));

        AuthPayload mfaReauth = reauthenticate(
            mfaLogin.accessToken(),
            "Prep3tud!2026",
            mfaTotpService.generateCodeForSecret(secret, Instant.now()),
            "198.51.100.19"
        );

        mockMvc.perform(post(CoreApiPaths.AUTH_MFA_TOTP_DISABLE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mfaReauth.accessToken())
                .header("X-Forwarded-For", "198.51.100.19")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "code", mfaTotpService.generateCodeForSecret(secret, Instant.now())
                ))))
            .andExpect(status().isNoContent())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.19")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.totpMfaEnabled").value(false));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.MFA_TOTP_DISABLED)).isEqualTo(1);
    }

    @Test
    void reauthenticateShouldRotateRefreshTokenBeforeTotpSetup() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        AuthPayload reauthenticatedAuth = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", "198.51.100.22");

        mockMvc.perform(post(CoreApiPaths.AUTH_REFRESH)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.22")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", initialAuth.refreshToken()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));

        mockMvc.perform(post(CoreApiPaths.AUTH_REFRESH)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.22")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", reauthenticatedAuth.refreshToken()))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").isNotEmpty());

        mockMvc.perform(post(CoreApiPaths.AUTH_MFA_TOTP_SETUP)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.22")
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.secret").isNotEmpty())
            .andExpect(jsonPath("$.otpauthUrl", containsString("otpauth://totp/")));
    }

    @Test
    void loginShouldRejectInvalidCredentialsWithUniformMessage() throws Exception {
        registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "bad-password"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
            .andExpect(jsonPath("$.message").value("Invalid email or password."));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.LOGIN_FAILURE)).isEqualTo(1);
    }

    @Test
    void loginShouldUseGenericResponseForUnverifiedAccounts() throws Exception {
        registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
            .andExpect(jsonPath("$.message").value("Invalid email or password."));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.LOGIN_FAILURE)).isEqualTo(1);
    }

    @Test
    void confirmEmailVerificationShouldAllowFutureLoginAndRefresh() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.10")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.emailVerified").value(true));

        MvcResult refreshResult = mockMvc.perform(post(CoreApiPaths.AUTH_REFRESH)
                .header("X-Forwarded-For", "198.51.100.10")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .cookie(new Cookie("authapi_refresh_token", initialAuth.refreshToken())))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("authapi_refresh_token=")))
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").isNotEmpty())
            .andReturn();

        AuthPayload rotatedAuth = readAuthPayload(refreshResult);

        mockMvc.perform(post(CoreApiPaths.AUTH_REFRESH)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.10")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", initialAuth.refreshToken()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGOUT)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.10")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", rotatedAuth.refreshToken()))))
            .andExpect(status().isNoContent())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.LOGIN_SUCCESS)).isEqualTo(1);
        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.LOGOUT)).isEqualTo(1);
    }

    @Test
    void changePasswordShouldInvalidateRefreshCookiesAndStaleAccessTokens() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_CHANGE_PASSWORD)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + initialAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.11")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "currentPassword", "Prep3tud!2026",
                    "newPassword", "Nuev4Clave!2026"
                ))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("REAUTHENTICATION_REQUIRED"));

        AuthPayload reauthenticatedAuth = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", "198.51.100.11");

        mockMvc.perform(post(CoreApiPaths.AUTH_CHANGE_PASSWORD)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.11")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "currentPassword", "Prep3tud!2026",
                    "newPassword", "Nuev4Clave!2026"
                ))))
            .andExpect(status().isNoContent())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        mockMvc.perform(get(CoreApiPaths.ME)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken()))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("STALE_ACCESS_TOKEN"));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.11")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.11")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Nuev4Clave!2026"
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.emailVerified").value(true));

        mockMvc.perform(post(CoreApiPaths.AUTH_REFRESH)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.11")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", initialAuth.refreshToken()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.PASSWORD_CHANGE)).isEqualTo(1);
        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.STEP_UP_SUCCESS)).isEqualTo(1);
    }

    @Test
    void reauthenticateShouldRotateSessionAndInvalidatePreviousTokens() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        AuthPayload reauthenticatedAuth = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", "198.51.100.14");

        mockMvc.perform(get(CoreApiPaths.ME)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + initialAuth.accessToken()))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("STALE_ACCESS_TOKEN"));

        mockMvc.perform(post(CoreApiPaths.AUTH_REFRESH)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.14")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", initialAuth.refreshToken()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));

        mockMvc.perform(get(CoreApiPaths.ME)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("thomas@example.com"));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.STEP_UP_SUCCESS)).isEqualTo(1);
    }

    @Test
    void changeEmailShouldRequireRecentReauthenticationAndVerification() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_CHANGE_EMAIL)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + initialAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.15")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of("newEmail", "nuevo@example.com"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("REAUTHENTICATION_REQUIRED"));

        AuthPayload reauthenticatedAuth = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", "198.51.100.15");

        mockMvc.perform(post(CoreApiPaths.AUTH_CHANGE_EMAIL)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.15")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of("newEmail", "nuevo@example.com"))))
            .andExpect(status().isNoContent())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        assertThat(verificationEmailSender.tokenFor("nuevo@example.com")).isNotBlank();

        mockMvc.perform(get(CoreApiPaths.ME)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken()))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("STALE_ACCESS_TOKEN"));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.15")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "nuevo@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));

        confirmEmail("nuevo@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.15")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "nuevo@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user.email").value("nuevo@example.com"))
            .andExpect(jsonPath("$.user.emailVerified").value(true));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.EMAIL_CHANGE)).isEqualTo(1);
    }

    @Test
    void logoutAllSessionsShouldRequireRecentReauthenticationAndInvalidateCurrentSession() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGOUT_ALL_SESSIONS)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + initialAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.16")
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("REAUTHENTICATION_REQUIRED"));

        AuthPayload reauthenticatedAuth = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", "198.51.100.16");

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGOUT_ALL_SESSIONS)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.16")
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isNoContent())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        mockMvc.perform(get(CoreApiPaths.ME)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken()))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("STALE_ACCESS_TOKEN"));

        mockMvc.perform(post(CoreApiPaths.AUTH_REFRESH)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.16")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("refreshToken", reauthenticatedAuth.refreshToken()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.LOGOUT_ALL_SESSIONS)).isEqualTo(1);
    }

    @Test
    void deleteAccountShouldRequireRecentReauthenticationAndDisableLogin() throws Exception {
        AuthPayload initialAuth = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_DELETE_ACCOUNT)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + initialAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.17")
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.code").value("REAUTHENTICATION_REQUIRED"));

        AuthPayload reauthenticatedAuth = reauthenticate(initialAuth.accessToken(), "Prep3tud!2026", "198.51.100.17");

        mockMvc.perform(post(CoreApiPaths.AUTH_DELETE_ACCOUNT)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken())
                .header("X-Forwarded-For", "198.51.100.17")
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isNoContent())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        mockMvc.perform(get(CoreApiPaths.ME)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + reauthenticatedAuth.accessToken()))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.17")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.ACCOUNT_DELETED)).isEqualTo(1);
    }

    @Test
    void forgotAndResetPasswordShouldUseGenericResponsesAndRotateCredentials() throws Exception {
        registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_FORGOT_PASSWORD)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.12")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("email", "thomas@example.com"))))
            .andExpect(status().isAccepted());

        assertThat(passwordResetEmailSender.urlFor("thomas@example.com"))
            .contains("http://localhost:8080/reset-password?token=");

        String resetToken = passwordResetEmailSender.tokenFor("thomas@example.com");
        assertThat(resetToken).isNotBlank();

        mockMvc.perform(post(CoreApiPaths.AUTH_RESET_PASSWORD)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.12")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "token", resetToken,
                    "newPassword", "Reset!Clave2026"
                ))))
            .andExpect(status().isNoContent());

        mockMvc.perform(post(CoreApiPaths.AUTH_RESET_PASSWORD)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.12")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "token", "invalid-token",
                    "newPassword", "Reset!Clave2026"
                ))))
            .andExpect(status().isNoContent());

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.12")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Prep3tud!2026"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.12")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "thomas@example.com",
                    "password", "Reset!Clave2026"
                ))))
            .andExpect(status().isOk());

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.PASSWORD_RESET)).isEqualTo(1);
    }

    @Test
    void resetPasswordShouldValidateWeakPasswordsBeforeTokenResolution() throws Exception {
        registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        mockMvc.perform(post(CoreApiPaths.AUTH_FORGOT_PASSWORD)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.13")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("email", "thomas@example.com"))))
            .andExpect(status().isAccepted());

        String validResetToken = passwordResetEmailSender.tokenFor("thomas@example.com");
        assertThat(validResetToken).isNotBlank();

        mockMvc.perform(post(CoreApiPaths.AUTH_RESET_PASSWORD)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.13")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "token", validResetToken,
                    "newPassword", "short"
                ))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.fieldErrors.newPassword").value("Password must be between 12 and 72 characters."));

        mockMvc.perform(post(CoreApiPaths.AUTH_RESET_PASSWORD)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.13")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "token", "invalid-token",
                    "newPassword", "short"
                ))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.fieldErrors.newPassword").value("Password must be between 12 and 72 characters."));
    }

    @Test
    void loginShouldRateLimitByIpAndEmail() throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("X-Forwarded-For", "198.51.100.20")
                    .header(HttpHeaders.USER_AGENT, "auth-test")
                    .content(objectMapper.writeValueAsBytes(Map.of(
                        "email", "missing@example.com",
                        "password", "Wrong!Clave2026"
                    ))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        }

        mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.20")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", "missing@example.com",
                    "password", "Wrong!Clave2026"
                ))))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.code").value("AUTH_RATE_LIMITED"));
    }

    @Test
    void forgotPasswordShouldRateLimitGenerically() throws Exception {
        for (int attempt = 0; attempt < 3; attempt++) {
            mockMvc.perform(post(CoreApiPaths.AUTH_FORGOT_PASSWORD)
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("X-Forwarded-For", "198.51.100.21")
                    .header(HttpHeaders.USER_AGENT, "auth-test")
                    .content(objectMapper.writeValueAsBytes(Map.of("email", "missing@example.com"))))
                .andExpect(status().isAccepted());
        }

        mockMvc.perform(post(CoreApiPaths.AUTH_FORGOT_PASSWORD)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.21")
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of("email", "missing@example.com"))))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.code").value("AUTH_RATE_LIMITED"));
    }

    @Test
    void refreshRotationShouldAllowOnlyOneConcurrentWinnerAndAuditReuse() throws Exception {
        AuthPayload authPayload = registerUser("thomas@example.com", "Prep3tud!2026", "Thomas Serna");
        confirmEmail("thomas@example.com");

        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        try {
            Future<Object> first = executor.submit(() -> rotateOnce(authPayload.refreshToken(), ready, start));
            Future<Object> second = executor.submit(() -> rotateOnce(authPayload.refreshToken(), ready, start));

            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            Object firstResult = first.get(5, TimeUnit.SECONDS);
            Object secondResult = second.get(5, TimeUnit.SECONDS);

            long successfulRotations = java.util.stream.Stream.of(firstResult, secondResult)
                .filter(RefreshTokenService.RefreshSession.class::isInstance)
                .count();
            long failedRotations = java.util.stream.Stream.of(firstResult, secondResult)
                .filter(ApiException.class::isInstance)
                .count();

            assertThat(successfulRotations).isEqualTo(1);
            assertThat(failedRotations).isEqualTo(1);
        } finally {
            executor.shutdownNow();
        }

        try {
            refreshTokenService.rotate(authPayload.refreshToken(), new AuthRequestMetadata("198.51.100.30", "auth-test"));
        } catch (ApiException ignored) {
        }

        assertThat(authAuditEventRepository.countByEventType(AuthAuditEventType.REFRESH_REUSE)).isEqualTo(1);
    }

    private Object rotateOnce(String refreshToken, CountDownLatch ready, CountDownLatch start) throws Exception {
        ready.countDown();
        start.await(5, TimeUnit.SECONDS);
        try {
            return refreshTokenService.rotate(refreshToken, new AuthRequestMetadata("198.51.100.30", "auth-test"));
        } catch (ApiException exception) {
            return exception;
        }
    }

    private void confirmEmail(String email) throws Exception {
        String token = verificationEmailSender.tokenFor(email);
        assertThat(token).isNotBlank();

        mockMvc.perform(post(CoreApiPaths.AUTH_EMAIL_VERIFICATION_CONFIRM)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of("token", token))))
            .andExpect(status().isNoContent());
    }

    private AuthPayload registerUser(String email, String password, String fullName) throws Exception {
        MvcResult registerResult = mockMvc.perform(post(CoreApiPaths.AUTH_REGISTER)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", email,
                    "password", password,
                    "fullName", fullName
                ))))
            .andExpect(status().isCreated())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("authapi_refresh_token=")))
            .andExpect(jsonPath("$.tokenType").value("Bearer"))
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").isNotEmpty())
            .andExpect(jsonPath("$.user.email").value(email))
            .andExpect(jsonPath("$.user.roles", hasItem("USER")))
            .andExpect(jsonPath("$.user.emailVerified").value(false))
            .andReturn();

        return readAuthPayload(registerResult);
    }

    private AuthPayload reauthenticate(String accessToken, String password, String clientIp) throws Exception {
        return reauthenticate(accessToken, password, null, clientIp);
    }

    private AuthPayload reauthenticate(String accessToken, String password, String mfaCode, String clientIp) throws Exception {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("password", password);
        if (mfaCode != null) {
            body.put("mfaCode", mfaCode);
        }
        MvcResult reauthenticateResult = mockMvc.perform(post(CoreApiPaths.AUTH_REAUTHENTICATE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header("X-Forwarded-For", clientIp)
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(body)))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("authapi_refresh_token=")))
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").isNotEmpty())
            .andReturn();

        return readAuthPayload(reauthenticateResult);
    }

    private AuthPayload readAuthPayload(MvcResult result) throws Exception {
        JsonNode jsonNode = objectMapper.readTree(result.getResponse().getContentAsByteArray());
        return new AuthPayload(
            jsonNode.get("accessToken").asText(),
            jsonNode.get("refreshToken").asText()
        );
    }

    private String beginTotpSetup(String accessToken, String clientIp) throws Exception {
        MvcResult setupResult = mockMvc.perform(post(CoreApiPaths.AUTH_MFA_TOTP_SETUP)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header("X-Forwarded-For", clientIp)
                .header(HttpHeaders.USER_AGENT, "auth-test"))
            .andExpect(status().isOk())
            .andReturn();

        return objectMapper.readTree(setupResult.getResponse().getContentAsByteArray()).get("secret").asText();
    }

    private void confirmTotpSetup(String accessToken, String secret, String clientIp) throws Exception {
        mockMvc.perform(post(CoreApiPaths.AUTH_MFA_TOTP_CONFIRM)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header("X-Forwarded-For", clientIp)
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "code", mfaTotpService.generateCodeForSecret(secret, Instant.now())
                ))))
            .andExpect(status().isNoContent());
    }

    private AuthPayload loginWithTotp(String email, String password, String secret, String clientIp) throws Exception {
        MvcResult loginResult = mockMvc.perform(post(CoreApiPaths.AUTH_LOGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", clientIp)
                .header(HttpHeaders.USER_AGENT, "auth-test")
                .content(objectMapper.writeValueAsBytes(Map.of(
                    "email", email,
                    "password", password,
                    "mfaCode", mfaTotpService.generateCodeForSecret(secret, Instant.now())
                ))))
            .andExpect(status().isOk())
            .andReturn();

        return readAuthPayload(loginResult);
    }

    private record AuthPayload(String accessToken, String refreshToken) {
    }
}
