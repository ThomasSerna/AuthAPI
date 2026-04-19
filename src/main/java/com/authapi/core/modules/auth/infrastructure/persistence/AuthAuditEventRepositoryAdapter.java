package com.authapi.core.modules.auth.infrastructure.persistence;

import com.authapi.core.modules.auth.domain.model.AuthAuditEvent;
import com.authapi.core.modules.auth.domain.repository.AuthAuditEventRepository;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;

import org.springframework.stereotype.Repository;

@Repository
public class AuthAuditEventRepositoryAdapter implements AuthAuditEventRepository {

    private final JpaAuthAuditEventRepository jpaAuthAuditEventRepository;

    public AuthAuditEventRepositoryAdapter(JpaAuthAuditEventRepository jpaAuthAuditEventRepository) {
        this.jpaAuthAuditEventRepository = jpaAuthAuditEventRepository;
    }

    @Override
    public AuthAuditEvent save(AuthAuditEvent event) {
        return jpaAuthAuditEventRepository.save(event);
    }

    @Override
    public long countByEventType(AuthAuditEventType eventType) {
        return jpaAuthAuditEventRepository.countByEventType(eventType);
    }
}
