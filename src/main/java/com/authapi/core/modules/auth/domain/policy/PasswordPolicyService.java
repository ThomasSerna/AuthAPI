package com.authapi.core.modules.auth.domain.policy;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.authapi.core.common.exception.ApiValidationException;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class PasswordPolicyService {

    private static final int MIN_PASSWORD_LENGTH = 12;

    private static final int MAX_PASSWORD_LENGTH = 72;

    private static final Set<String> COMMON_PASSWORDS = Set.of(
        "password",
        "password123",
        "qwerty123",
        "123456789012",
        "admin123456",
        "letmein123",
        "welcome123",
        "AuthAPI123"
    );

    public void validateForRegistration(String password, String email, String fullName) {
        validate(password, email, fullName, "password");
    }

    public void validateForPasswordChange(String password, String email, String fullName) {
        validate(password, email, fullName, "newPassword");
    }

    public void validateForPasswordReset(String password) {
        validate(password, null, null, "newPassword");
    }

    private void validate(String password, String email, String fullName, String fieldName) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        if (!StringUtils.hasText(password)) {
            fieldErrors.put(fieldName, "Password is required.");
            throw new ApiValidationException("Request validation failed.", fieldErrors);
        }

        if (password.length() < MIN_PASSWORD_LENGTH || password.length() > MAX_PASSWORD_LENGTH) {
            fieldErrors.put(fieldName, "Password must be between 12 and 72 characters.");
        } else if (characterClasses(password) < 3) {
            fieldErrors.put(
                fieldName,
                "Password must contain at least three of: uppercase letters, lowercase letters, numbers, and symbols."
            );
        } else if (COMMON_PASSWORDS.contains(password.trim().toLowerCase(Locale.ROOT))) {
            fieldErrors.put(fieldName, "Password is too common. Choose a less predictable one.");
        } else if ((StringUtils.hasText(email) || StringUtils.hasText(fullName))
            && containsPersonalInfo(password, email, fullName)) {
            fieldErrors.put(fieldName, "Password must not contain your email or name.");
        }

        if (!fieldErrors.isEmpty()) {
            throw new ApiValidationException("Request validation failed.", fieldErrors);
        }
    }

    private int characterClasses(String password) {
        boolean hasLowercase = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUppercase = password.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSymbol = password.chars().anyMatch(character ->
            !Character.isLetterOrDigit(character) && !Character.isWhitespace(character)
        );

        int classes = 0;
        if (hasLowercase) {
            classes++;
        }
        if (hasUppercase) {
            classes++;
        }
        if (hasDigit) {
            classes++;
        }
        if (hasSymbol) {
            classes++;
        }
        return classes;
    }

    private boolean containsPersonalInfo(String password, String email, String fullName) {
        String normalizedPassword = password.toLowerCase(Locale.ROOT);
        String emailLocalPart = extractEmailLocalPart(email);
        if (emailLocalPart.length() >= 4 && normalizedPassword.contains(emailLocalPart)) {
            return true;
        }

        String[] nameParts = fullName == null ? new String[0] : fullName.toLowerCase(Locale.ROOT).split("\\s+");
        for (String namePart : nameParts) {
            if (namePart.length() >= 4 && normalizedPassword.contains(namePart)) {
                return true;
            }
        }
        return false;
    }

    private String extractEmailLocalPart(String email) {
        if (!StringUtils.hasText(email)) {
            return "";
        }
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        int atIndex = normalizedEmail.indexOf('@');
        return atIndex > 0 ? normalizedEmail.substring(0, atIndex) : normalizedEmail;
    }
}
