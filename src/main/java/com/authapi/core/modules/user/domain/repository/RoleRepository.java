package com.authapi.core.modules.user.domain.repository;

import java.util.Optional;

import com.authapi.core.modules.user.domain.model.Role;

public interface RoleRepository {

    Optional<Role> findByName(String name);
}
