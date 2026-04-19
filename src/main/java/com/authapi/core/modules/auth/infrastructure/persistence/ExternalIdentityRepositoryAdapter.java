package com.authapi.core.modules.auth.infrastructure.persistence;

import java.util.Optional;

import com.authapi.core.modules.auth.domain.model.ExternalIdentity;
import com.authapi.core.modules.auth.domain.repository.ExternalIdentityRepository;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;

import org.springframework.stereotype.Repository;

@Repository
public class ExternalIdentityRepositoryAdapter implements ExternalIdentityRepository {

    private final JpaExternalIdentityRepository jpaExternalIdentityRepository;

    public ExternalIdentityRepositoryAdapter(JpaExternalIdentityRepository jpaExternalIdentityRepository) {
        this.jpaExternalIdentityRepository = jpaExternalIdentityRepository;
    }

    @Override
    public Optional<ExternalIdentity> findByProviderAndSubject(FederatedAuthProvider provider, String subject) {
        return jpaExternalIdentityRepository.findByProviderAndSubject(provider, subject);
    }

    @Override
    public ExternalIdentity save(ExternalIdentity externalIdentity) {
        return jpaExternalIdentityRepository.save(externalIdentity);
    }
}
