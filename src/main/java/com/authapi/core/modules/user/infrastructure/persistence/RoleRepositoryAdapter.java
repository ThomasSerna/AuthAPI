package com.authapi.core.modules.user.infrastructure.persistence;

import java.util.Optional;

import com.authapi.core.modules.user.domain.model.Role;
import com.authapi.core.modules.user.domain.repository.RoleRepository;

import org.springframework.stereotype.Repository;

@Repository
public class RoleRepositoryAdapter implements RoleRepository {

    private final JpaRoleRepository jpaRoleRepository;

    public RoleRepositoryAdapter(JpaRoleRepository jpaRoleRepository) {
        this.jpaRoleRepository = jpaRoleRepository;
    }

    @Override
    public Optional<Role> findByName(String name) {
        return jpaRoleRepository.findByName(name);
    }
}
