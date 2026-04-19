package com.authapi.core.modules.user.infrastructure.persistence;

import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.user.domain.model.User;

import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaUserRepository extends JpaRepository<User, UUID> {

    boolean existsByEmailIgnoreCase(String email);

    Optional<User> findByEmailIgnoreCase(String email);
}
