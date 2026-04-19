package com.authapi.core.modules.auth.domain.repository;

import com.authapi.core.modules.auth.domain.model.AuthAuditEvent;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;

public interface AuthAuditEventRepository {

    AuthAuditEvent save(AuthAuditEvent event);

    long countByEventType(AuthAuditEventType eventType);
}
