package com.authapi.core.modules.auth.domain.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.auth.domain.model.TotpSetup;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.service.UserService;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional(readOnly = true)
public class MfaTotpService {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final SecureRandom secureRandom = new SecureRandom();

    private final SecurityProperties securityProperties;

    private final UserService userService;

    private final RefreshTokenService refreshTokenService;

    private final AuthAuditService authAuditService;

    private final Clock clock = Clock.systemUTC();

    public MfaTotpService(
        SecurityProperties securityProperties,
        UserService userService,
        RefreshTokenService refreshTokenService,
        AuthAuditService authAuditService
    ) {
        this.securityProperties = securityProperties;
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.authAuditService = authAuditService;
    }

    @Transactional
    public TotpSetup beginSetup(User user, AuthRequestMetadata requestMetadata) {
        if (user.isTotpMfaEnabled()) {
            throw new ApiException(
                HttpStatus.CONFLICT,
                "MFA_ALREADY_ENABLED",
                "TOTP multi-factor authentication is already enabled."
            );
        }

        String secret = generateSecret();
        userService.storePendingTotpSecret(user, encrypt(secret));
        authAuditService.record(
            AuthAuditEventType.MFA_TOTP_SETUP_INITIATED,
            user,
            user.getEmail(),
            requestMetadata,
            "totp setup initiated"
        );

        return new TotpSetup(
            secret,
            buildOtpAuthUrl(secret, user),
            securityProperties.getMfaTotp().getIssuer(),
            user.getEmail()
        );
    }

    @Transactional
    public void confirmSetup(User user, String code, AuthRequestMetadata requestMetadata) {
        if (!StringUtils.hasText(user.getMfaTotpPendingSecretCiphertext())) {
            throw new ApiException(
                HttpStatus.BAD_REQUEST,
                "MFA_SETUP_NOT_INITIATED",
                "TOTP setup has not been initiated."
            );
        }

        String secret = decrypt(user.getMfaTotpPendingSecretCiphertext());
        if (!isCodeValid(secret, code, Instant.now(clock))) {
            authAuditService.record(
                AuthAuditEventType.MFA_FAILURE,
                user,
                user.getEmail(),
                requestMetadata,
                "invalid totp code during setup confirmation"
            );
            throw invalidTotpCodeException();
        }

        userService.enableTotpMfa(user, encrypt(secret), Instant.now(clock));
        refreshTokenService.revokeAllForUser(user);
        authAuditService.record(
            AuthAuditEventType.MFA_TOTP_ENABLED,
            user,
            user.getEmail(),
            requestMetadata,
            "totp enabled"
        );
    }

    @Transactional
    public void disable(User user, String code, AuthRequestMetadata requestMetadata) {
        if (!user.isTotpMfaEnabled()) {
            return;
        }

        if (!isCodeValidForUser(user, code)) {
            authAuditService.record(
                AuthAuditEventType.MFA_FAILURE,
                user,
                user.getEmail(),
                requestMetadata,
                "invalid totp code during disable"
            );
            throw invalidTotpCodeException();
        }

        userService.disableTotpMfa(user);
        refreshTokenService.revokeAllForUser(user);
        authAuditService.record(
            AuthAuditEventType.MFA_TOTP_DISABLED,
            user,
            user.getEmail(),
            requestMetadata,
            "totp disabled"
        );
    }

    public boolean isCodeValidForUser(User user, String code) {
        if (!user.isTotpMfaEnabled()) {
            return false;
        }
        return isCodeValid(decrypt(user.getMfaTotpSecretCiphertext()), code, Instant.now(clock));
    }

    public String generateCodeForSecret(String secret, Instant instant) {
        byte[] secretBytes = decodeBase32(secret);
        long periodSeconds = Math.max(1L, securityProperties.getMfaTotp().getPeriod().getSeconds());
        long counter = Math.floorDiv(instant.getEpochSecond(), periodSeconds);
        byte[] counterBytes = new byte[8];
        for (int index = 7; index >= 0; index--) {
            counterBytes[index] = (byte) (counter & 0xFF);
            counter >>>= 8;
        }

        byte[] hmac = hmacSha1(secretBytes, counterBytes);
        int offset = hmac[hmac.length - 1] & 0x0F;
        int binary = ((hmac[offset] & 0x7F) << 24)
            | ((hmac[offset + 1] & 0xFF) << 16)
            | ((hmac[offset + 2] & 0xFF) << 8)
            | (hmac[offset + 3] & 0xFF);

        int digits = securityProperties.getMfaTotp().getDigits();
        int divisor = 1;
        for (int i = 0; i < digits; i++) {
            divisor *= 10;
        }
        int otp = binary % divisor;
        return String.format("%0" + digits + "d", otp);
    }

    private boolean isCodeValid(String secret, String code, Instant instant) {
        if (!StringUtils.hasText(code) || !code.chars().allMatch(Character::isDigit)) {
            return false;
        }

        int allowedDriftWindows = Math.max(0, securityProperties.getMfaTotp().getAllowedDriftWindows());
        for (int drift = -allowedDriftWindows; drift <= allowedDriftWindows; drift++) {
            Instant candidateInstant = instant.plusSeconds((long) drift * securityProperties.getMfaTotp().getPeriod().getSeconds());
            if (MessageDigest.isEqual(
                generateCodeForSecret(secret, candidateInstant).getBytes(StandardCharsets.UTF_8),
                code.getBytes(StandardCharsets.UTF_8)
            )) {
                return true;
            }
        }
        return false;
    }

    private String buildOtpAuthUrl(String secret, User user) {
        String issuer = securityProperties.getMfaTotp().getIssuer();
        String label = issuer + ":" + user.getEmail();
        return "otpauth://totp/"
            + urlEncode(label)
            + "?secret=" + secret
            + "&issuer=" + urlEncode(issuer)
            + "&algorithm=SHA1"
            + "&digits=" + securityProperties.getMfaTotp().getDigits()
            + "&period=" + Math.max(1L, securityProperties.getMfaTotp().getPeriod().getSeconds());
    }

    private String generateSecret() {
        byte[] secretBytes = new byte[20];
        secureRandom.nextBytes(secretBytes);
        return encodeBase32(secretBytes);
    }

    private String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey(), new GCMParameterSpec(128, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return URL_ENCODER.encodeToString(iv) + "." + URL_ENCODER.encodeToString(ciphertext);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to encrypt TOTP secret.", exception);
        }
    }

    private String decrypt(String encryptedValue) {
        try {
            String[] parts = encryptedValue.split("\\.", 2);
            if (parts.length != 2) {
                throw new IllegalStateException("Stored TOTP secret has an invalid format.");
            }

            byte[] iv = URL_DECODER.decode(parts[0]);
            byte[] ciphertext = URL_DECODER.decode(parts[1]);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey(), new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to decrypt TOTP secret.", exception);
        }
    }

    private SecretKeySpec encryptionKey() {
        byte[] keyBytes = Arrays.copyOf(
            sha256(securityProperties.getMfaTotp().getEncryptionSecret().getBytes(StandardCharsets.UTF_8)),
            32
        );
        return new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] hmacSha1(byte[] secretBytes, byte[] value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secretBytes, "HmacSHA1"));
            return mac.doFinal(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to calculate TOTP HMAC.", exception);
        }
    }

    private byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is not available in this runtime.", exception);
        }
    }

    private String encodeBase32(byte[] value) {
        StringBuilder result = new StringBuilder((value.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte currentByte : value) {
            buffer = (buffer << 8) | (currentByte & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            result.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return result.toString();
    }

    private byte[] decodeBase32(String value) {
        String normalized = value == null ? "" : value.trim().replace("=", "").replace(" ", "").toUpperCase();
        byte[] result = new byte[normalized.length() * 5 / 8];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;
        for (int i = 0; i < normalized.length(); i++) {
            int alphabetIndex = BASE32_ALPHABET.indexOf(normalized.charAt(i));
            if (alphabetIndex < 0) {
                throw new IllegalArgumentException("Invalid Base32 secret.");
            }
            buffer = (buffer << 5) | alphabetIndex;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                result[index++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return index == result.length ? result : Arrays.copyOf(result, index);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private ApiException invalidTotpCodeException() {
        return new ApiException(
            HttpStatus.UNAUTHORIZED,
            "INVALID_MFA_CODE",
            "Invalid authentication code."
        );
    }
}
