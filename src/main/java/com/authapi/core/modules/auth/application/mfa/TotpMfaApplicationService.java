package com.authapi.core.modules.auth.application.mfa;

import com.authapi.core.common.security.CurrentUserService;
import com.authapi.core.modules.auth.domain.model.TotpSetup;
import com.authapi.core.modules.auth.domain.service.MfaTotpService;
import com.authapi.core.modules.auth.domain.support.AuthRequestMetadata;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class TotpMfaApplicationService {

    private final MfaTotpService mfaTotpService;

    private final CurrentUserService currentUserService;

    public TotpMfaApplicationService(
        MfaTotpService mfaTotpService,
        CurrentUserService currentUserService
    ) {
        this.mfaTotpService = mfaTotpService;
        this.currentUserService = currentUserService;
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public TotpSetup beginSetup(AuthRequestMetadata requestMetadata) {
        return mfaTotpService.beginSetup(
            currentUserService.getCurrentUserRequiringRecentReauthentication(),
            requestMetadata
        );
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void confirmSetup(String code, AuthRequestMetadata requestMetadata) {
        mfaTotpService.confirmSetup(
            currentUserService.getCurrentUserRequiringRecentReauthentication(),
            code,
            requestMetadata
        );
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void disable(String code, AuthRequestMetadata requestMetadata) {
        mfaTotpService.disable(
            currentUserService.getCurrentUserRequiringRecentReauthentication(),
            code,
            requestMetadata
        );
    }
}
