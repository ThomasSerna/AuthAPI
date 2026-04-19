package com.authapi.core.modules.user.domain.model;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UuidGenerator;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
    name = "users",
    uniqueConstraints = {
        @UniqueConstraint(name = "uk_users_email", columnNames = "email")
    }
)
public class User {

    @Id
    @UuidGenerator
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "id", nullable = false, updatable = false, length = 36)
    private UUID id;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "full_name", nullable = false, length = 255)
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "email_verified_at")
    private Instant emailVerifiedAt;

    @Column(name = "password_changed_at", nullable = false)
    private Instant passwordChangedAt;

    @Column(name = "session_version", nullable = false)
    private int sessionVersion;

    @Column(name = "mfa_totp_secret_ciphertext", length = 1024)
    private String mfaTotpSecretCiphertext;

    @Column(name = "mfa_totp_pending_secret_ciphertext", length = 1024)
    private String mfaTotpPendingSecretCiphertext;

    @Column(name = "mfa_totp_enabled_at")
    private Instant mfaTotpEnabledAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new LinkedHashSet<>();

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.passwordChangedAt == null) {
            this.passwordChangedAt = now;
        }
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE;
    }

    public Instant getEmailVerifiedAt() {
        return emailVerifiedAt;
    }

    public void setEmailVerifiedAt(Instant emailVerifiedAt) {
        this.emailVerifiedAt = emailVerifiedAt;
    }

    public Instant getPasswordChangedAt() {
        return passwordChangedAt;
    }

    public void setPasswordChangedAt(Instant passwordChangedAt) {
        this.passwordChangedAt = passwordChangedAt;
    }

    public boolean isEmailVerified() {
        return emailVerifiedAt != null;
    }

    public int getSessionVersion() {
        return sessionVersion;
    }

    public void setSessionVersion(int sessionVersion) {
        this.sessionVersion = sessionVersion;
    }

    public String getMfaTotpSecretCiphertext() {
        return mfaTotpSecretCiphertext;
    }

    public void setMfaTotpSecretCiphertext(String mfaTotpSecretCiphertext) {
        this.mfaTotpSecretCiphertext = mfaTotpSecretCiphertext;
    }

    public String getMfaTotpPendingSecretCiphertext() {
        return mfaTotpPendingSecretCiphertext;
    }

    public void setMfaTotpPendingSecretCiphertext(String mfaTotpPendingSecretCiphertext) {
        this.mfaTotpPendingSecretCiphertext = mfaTotpPendingSecretCiphertext;
    }

    public Instant getMfaTotpEnabledAt() {
        return mfaTotpEnabledAt;
    }

    public void setMfaTotpEnabledAt(Instant mfaTotpEnabledAt) {
        this.mfaTotpEnabledAt = mfaTotpEnabledAt;
    }

    public boolean isTotpMfaEnabled() {
        return mfaTotpEnabledAt != null && mfaTotpSecretCiphertext != null;
    }
}
