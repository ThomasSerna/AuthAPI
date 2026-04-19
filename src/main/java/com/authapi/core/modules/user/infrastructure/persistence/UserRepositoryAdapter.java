package com.authapi.core.modules.user.infrastructure.persistence;

import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.user.domain.model.User;
import com.authapi.core.modules.user.domain.repository.UserRepository;

import org.springframework.stereotype.Repository;

@Repository
public class UserRepositoryAdapter implements UserRepository {

    private final JpaUserRepository jpaUserRepository;

    public UserRepositoryAdapter(JpaUserRepository jpaUserRepository) {
        this.jpaUserRepository = jpaUserRepository;
    }

    @Override
    public boolean existsByEmailIgnoreCase(String email) {
        return jpaUserRepository.existsByEmailIgnoreCase(email);
    }

    @Override
    public Optional<User> findByEmailIgnoreCase(String email) {
        return jpaUserRepository.findByEmailIgnoreCase(email);
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jpaUserRepository.findById(id);
    }

    @Override
    public User save(User user) {
        return jpaUserRepository.save(user);
    }

    @Override
    public User saveAndFlush(User user) {
        return jpaUserRepository.saveAndFlush(user);
    }
}
