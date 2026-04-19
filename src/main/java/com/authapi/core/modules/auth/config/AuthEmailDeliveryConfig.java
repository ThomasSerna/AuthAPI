package com.authapi.core.modules.auth.config;

import com.authapi.core.common.config.MailDeliveryProperties;
import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.modules.auth.domain.port.PasswordResetEmailSender;
import com.authapi.core.modules.auth.domain.port.VerificationEmailSender;
import com.authapi.core.modules.auth.infrastructure.email.LoggingPasswordResetEmailSender;
import com.authapi.core.modules.auth.infrastructure.email.LoggingVerificationEmailSender;
import com.authapi.core.modules.auth.infrastructure.email.SmtpAuthEmailSender;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
@EnableConfigurationProperties(MailDeliveryProperties.class)
public class AuthEmailDeliveryConfig {

    @Bean
    @ConditionalOnProperty(prefix = "authapi.mail", name = "enabled", havingValue = "true")
    public SmtpAuthEmailSender smtpAuthEmailSender(
        JavaMailSender javaMailSender,
        MailDeliveryProperties mailDeliveryProperties,
        SecurityProperties securityProperties
    ) {
        return new SmtpAuthEmailSender(javaMailSender, mailDeliveryProperties, securityProperties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "authapi.mail", name = "enabled", havingValue = "true")
    public VerificationEmailSender verificationEmailSender(SmtpAuthEmailSender smtpAuthEmailSender) {
        return smtpAuthEmailSender;
    }

    @Bean
    @ConditionalOnProperty(prefix = "authapi.mail", name = "enabled", havingValue = "true")
    public PasswordResetEmailSender passwordResetEmailSender(SmtpAuthEmailSender smtpAuthEmailSender) {
        return smtpAuthEmailSender;
    }

    @Bean
    @ConditionalOnProperty(prefix = "authapi.mail", name = "enabled", havingValue = "false", matchIfMissing = true)
    public VerificationEmailSender loggingVerificationEmailSender() {
        return new LoggingVerificationEmailSender();
    }

    @Bean
    @ConditionalOnProperty(prefix = "authapi.mail", name = "enabled", havingValue = "false", matchIfMissing = true)
    public PasswordResetEmailSender loggingPasswordResetEmailSender() {
        return new LoggingPasswordResetEmailSender();
    }
}
