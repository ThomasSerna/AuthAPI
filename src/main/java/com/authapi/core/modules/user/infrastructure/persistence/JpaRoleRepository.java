package com.authapi.core.modules.user.infrastructure.persistence;

import java.util.Optional;

import com.authapi.core.modules.user.domain.model.Role;

import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaRoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);
}
