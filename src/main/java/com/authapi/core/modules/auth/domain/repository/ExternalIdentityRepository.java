package com.authapi.core.modules.auth.domain.repository;

import java.util.Optional;

import com.authapi.core.modules.auth.domain.model.ExternalIdentity;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;

public interface ExternalIdentityRepository {

    Optional<ExternalIdentity> findByProviderAndSubject(FederatedAuthProvider provider, String subject);

    ExternalIdentity save(ExternalIdentity externalIdentity);
}
