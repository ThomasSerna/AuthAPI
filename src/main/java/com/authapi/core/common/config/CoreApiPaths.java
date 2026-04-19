package com.authapi.core.common.config;

public final class CoreApiPaths {

    public static final String V1 = "/api/v1";

    public static final String AUTH = V1 + "/auth";

    public static final String AUTH_REGISTER = AUTH + "/register";

    public static final String AUTH_LOGIN = AUTH + "/login";

    public static final String AUTH_LOGIN_GOOGLE = AUTH_LOGIN + "/google";

    public static final String AUTH_LOGIN_MICROSOFT = AUTH_LOGIN + "/microsoft";

    public static final String AUTH_REFRESH = AUTH + "/refresh";

    public static final String AUTH_LOGOUT = AUTH + "/logout";

    public static final String AUTH_REAUTHENTICATE = AUTH + "/reauthenticate";

    public static final String AUTH_CHANGE_PASSWORD = AUTH + "/change-password";

    public static final String AUTH_CHANGE_EMAIL = AUTH + "/change-email";

    public static final String AUTH_MFA_TOTP_SETUP = AUTH + "/mfa/totp/setup";

    public static final String AUTH_MFA_TOTP_CONFIRM = AUTH + "/mfa/totp/confirm";

    public static final String AUTH_MFA_TOTP_DISABLE = AUTH + "/mfa/totp/disable";

    public static final String AUTH_LOGOUT_ALL_SESSIONS = AUTH + "/logout-all-sessions";

    public static final String AUTH_DELETE_ACCOUNT = AUTH + "/delete-account";

    public static final String AUTH_EMAIL_VERIFICATION_REQUEST = AUTH + "/email-verification/request";

    public static final String AUTH_EMAIL_VERIFICATION_CONFIRM = AUTH + "/email-verification/confirm";

    public static final String AUTH_FORGOT_PASSWORD = AUTH + "/forgot-password";

    public static final String AUTH_RESET_PASSWORD = AUTH + "/reset-password";

    public static final String ME = V1 + "/me";

    private CoreApiPaths() {
    }
}
