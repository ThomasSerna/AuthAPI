package com.authapi.core.modules.auth.application.email;

import com.authapi.core.modules.auth.domain.service.EmailVerificationService;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class EmailVerificationApplicationService {

    private final EmailVerificationService emailVerificationService;

    public EmailVerificationApplicationService(EmailVerificationService emailVerificationService) {
        this.emailVerificationService = emailVerificationService;
    }

    @Transactional
    public void requestVerification(String email) {
        emailVerificationService.requestVerification(email);
    }

    @Transactional
    public void confirmVerification(String token) {
        emailVerificationService.confirmVerification(token);
    }
}
