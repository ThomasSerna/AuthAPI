package com.authapi.core.modules.auth.domain.service;

import java.time.Instant;
import java.util.Optional;

import com.authapi.core.modules.auth.domain.model.ExternalIdentity;
import com.authapi.core.modules.auth.domain.repository.ExternalIdentityRepository;
import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;
import com.authapi.core.modules.auth.domain.support.FederatedIdentity;
import com.authapi.core.modules.user.domain.model.User;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class ExternalIdentityService {

    private final ExternalIdentityRepository externalIdentityRepository;

    public ExternalIdentityService(ExternalIdentityRepository externalIdentityRepository) {
        this.externalIdentityRepository = externalIdentityRepository;
    }

    public Optional<User> findUser(FederatedAuthProvider provider, String subject) {
        return externalIdentityRepository.findByProviderAndSubject(provider, subject)
            .map(ExternalIdentity::getUser);
    }

    @Transactional
    public ExternalIdentity link(User user, FederatedIdentity federatedIdentity) {
        ExternalIdentity externalIdentity = externalIdentityRepository.findByProviderAndSubject(
            federatedIdentity.provider(),
            federatedIdentity.subject()
        ).orElseGet(ExternalIdentity::new);
        externalIdentity.setUser(user);
        externalIdentity.setProvider(federatedIdentity.provider());
        externalIdentity.setSubject(federatedIdentity.subject());
        externalIdentity.setEmail(federatedIdentity.email());
        externalIdentity.setLastLoginAt(Instant.now());
        return externalIdentityRepository.save(externalIdentity);
    }
}
