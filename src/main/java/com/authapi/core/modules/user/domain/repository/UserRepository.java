package com.authapi.core.modules.user.domain.repository;

import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.user.domain.model.User;

public interface UserRepository {

    boolean existsByEmailIgnoreCase(String email);

    Optional<User> findByEmailIgnoreCase(String email);

    Optional<User> findById(UUID id);

    User save(User user);

    User saveAndFlush(User user);
}
