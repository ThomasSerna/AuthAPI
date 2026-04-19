package com.authapi.core.modules.auth.infrastructure.persistence;

import com.authapi.core.modules.auth.domain.model.AuthAuditEvent;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;

import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaAuthAuditEventRepository extends JpaRepository<AuthAuditEvent, Long> {

    long countByEventType(AuthAuditEventType eventType);
}
