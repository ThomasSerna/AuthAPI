package com.authapi.core.modules.auth.domain.service;

import com.authapi.core.modules.auth.domain.support.FederatedAuthProvider;
import com.authapi.core.modules.auth.domain.support.FederatedIdentity;

public interface FederatedIdentityVerifier {

    FederatedIdentity verifyLoginToken(FederatedAuthProvider provider, String idToken);
}
