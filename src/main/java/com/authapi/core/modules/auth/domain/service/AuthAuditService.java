package com.authapi.core.modules.auth.domain.service;

import com.authapi.core.modules.auth.domain.model.AuthAuditEvent;
import com.authapi.core.modules.auth.domain.repository.AuthAuditEventRepository;
import com.authapi.core.modules.auth.domain.support.AuthAuditEventType;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;
import com.authapi.core.modules.user.domain.model.User;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

@Service
public class AuthAuditService {

    private final AuthAuditEventRepository authAuditEventRepository;

    public AuthAuditService(AuthAuditEventRepository authAuditEventRepository) {
        this.authAuditEventRepository = authAuditEventRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(
        AuthAuditEventType eventType,
        User user,
        String email,
        AuthRequestMetadata requestMetadata,
        String details
    ) {
        AuthAuditEvent event = new AuthAuditEvent();
        event.setEventType(eventType);
        event.setUserId(user == null ? null : user.getId());
        event.setEmail(email);
        event.setIpAddress(requestMetadata.clientIp());
        event.setUserAgent(requestMetadata.userAgent());
        event.setDetails(details);
        authAuditEventRepository.save(event);
    }
}
