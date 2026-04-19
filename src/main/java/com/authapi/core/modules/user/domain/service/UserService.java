package com.authapi.core.modules.user.domain.service;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.common.exception.ApiException;
import com.authapi.core.modules.user.domain.model.Role;
import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.model.UserStatus;
import com.authapi.core.modules.user.domain.repository.RoleRepository;
import com.authapi.core.modules.user.domain.repository.UserRepository;
import jakarta.persistence.EntityManager;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional(readOnly = true)
public class UserService {

    private static final String DEFAULT_ROLE = "USER";

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final EntityManager entityManager;

    public UserService(UserRepository userRepository, RoleRepository roleRepository, EntityManager entityManager) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.entityManager = entityManager;
    }

    @Transactional
    public User registerNewUser(String email, String passwordHash, String fullName) {
        return createUser(email, passwordHash, fullName, null);
    }

    @Transactional
    public User registerFederatedUser(String email, String passwordHash, String fullName, Instant emailVerifiedAt) {
        return createUser(email, passwordHash, fullName, emailVerifiedAt);
    }

    private User createUser(String email, String passwordHash, String fullName, Instant emailVerifiedAt) {
        String normalizedEmail = normalizeEmail(email);
        if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw new ApiException(
                HttpStatus.CONFLICT,
                "EMAIL_ALREADY_REGISTERED",
                "An account with this email already exists."
            );
        }
        Role userRole = roleRepository.findByName(DEFAULT_ROLE)
            .orElseThrow(() -> new ApiException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "ROLE_NOT_FOUND",
                "Default user role is not configured."
            ));

        User user = new User();
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordHash);
        user.setFullName(normalizeFullName(fullName));
        user.setStatus(UserStatus.ACTIVE);
        user.setEmailVerifiedAt(emailVerifiedAt);
        user.setPasswordChangedAt(Instant.now());
        user.setSessionVersion(0);
        user.getRoles().add(userRole);
        try {
            User savedUser = userRepository.saveAndFlush(user);
            entityManager.refresh(savedUser);
            return savedUser;
        } catch (DataIntegrityViolationException exception) {
            throw new ApiException(
                HttpStatus.CONFLICT,
                "EMAIL_ALREADY_REGISTERED",
                "An account with this email already exists."
            );
        }
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(normalizeEmail(email));
    }

    public User getRequiredUser(UUID userId) {
        return userRepository.findById(userId)
            .orElseThrow(() -> new ApiException(
                HttpStatus.UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication required."
            ));
    }

    @Transactional
    public void markEmailVerified(User user, Instant verifiedAt) {
        if (user.isEmailVerified()) {
            return;
        }
        user.setEmailVerifiedAt(verifiedAt);
        userRepository.save(user);
    }

    @Transactional
    public void changePassword(User user, String passwordHash, Instant changedAt) {
        user.setPasswordHash(passwordHash);
        user.setPasswordChangedAt(changedAt);
        bumpSessionVersion(user);
        userRepository.save(user);
    }

    @Transactional
    public void upgradePasswordHash(User user, String passwordHash) {
        user.setPasswordHash(passwordHash);
        userRepository.save(user);
    }

    @Transactional
    public void rotateSession(User user) {
        bumpSessionVersion(user);
        userRepository.save(user);
    }

    @Transactional
    public void changeEmail(User user, String newEmail) {
        String normalizedEmail = normalizeEmail(newEmail);
        if (normalizedEmail.equals(user.getEmail())) {
            throw new ApiException(
                HttpStatus.BAD_REQUEST,
                "EMAIL_UNCHANGED",
                "New email must be different from the current email."
            );
        }

        userRepository.findByEmailIgnoreCase(normalizedEmail)
            .filter(existingUser -> !existingUser.getId().equals(user.getId()))
            .ifPresent(existingUser -> {
                throw new ApiException(
                    HttpStatus.CONFLICT,
                    "EMAIL_ALREADY_REGISTERED",
                    "An account with this email already exists."
                );
            });

        user.setEmail(normalizedEmail);
        user.setEmailVerifiedAt(null);
        bumpSessionVersion(user);
        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException exception) {
            throw new ApiException(
                HttpStatus.CONFLICT,
                "EMAIL_ALREADY_REGISTERED",
                "An account with this email already exists."
            );
        }
    }

    @Transactional
    public void disableAccount(User user) {
        user.setStatus(UserStatus.DISABLED);
        user.setEmail("deleted+" + user.getId() + "+" + Instant.now().toEpochMilli() + "@deleted.authapi.local");
        user.setEmailVerifiedAt(null);
        user.setFullName("Deleted User");
        clearTotpMfa(user);
        bumpSessionVersion(user);
        userRepository.save(user);
    }

    @Transactional
    public void storePendingTotpSecret(User user, String pendingSecretCiphertext) {
        user.setMfaTotpPendingSecretCiphertext(pendingSecretCiphertext);
        userRepository.save(user);
    }

    @Transactional
    public void enableTotpMfa(User user, String secretCiphertext, Instant enabledAt) {
        user.setMfaTotpSecretCiphertext(secretCiphertext);
        user.setMfaTotpPendingSecretCiphertext(null);
        user.setMfaTotpEnabledAt(enabledAt);
        bumpSessionVersion(user);
        userRepository.save(user);
    }

    @Transactional
    public void disableTotpMfa(User user) {
        clearTotpMfa(user);
        bumpSessionVersion(user);
        userRepository.save(user);
    }

    public String normalizeEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return "";
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeFullName(String fullName) {
        return fullName == null ? "" : fullName.trim();
    }

    private void bumpSessionVersion(User user) {
        user.setSessionVersion(user.getSessionVersion() + 1);
    }

    private void clearTotpMfa(User user) {
        user.setMfaTotpSecretCiphertext(null);
        user.setMfaTotpPendingSecretCiphertext(null);
        user.setMfaTotpEnabledAt(null);
    }
}
