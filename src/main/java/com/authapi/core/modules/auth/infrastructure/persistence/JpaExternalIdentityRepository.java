package com.authapi.core.modules.auth.infrastructure.persistence;

import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.ExternalIdentity;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;

import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaExternalIdentityRepository extends JpaRepository<ExternalIdentity, UUID> {

    Optional<ExternalIdentity> findByProviderAndSubject(FederatedAuthProvider provider, String subject);
}
