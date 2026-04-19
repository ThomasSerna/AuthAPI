package com.authapi.core.modules.auth.infrastructure.email;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Properties;

import com.authapi.core.common.config.MailDeliveryProperties;
import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.modules.user.domain.model.User;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;

import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSender;

class SmtpAuthEmailSenderTests {

    @Test
    void verificationEmailsShouldIncludeConfiguredLinkAndSenderMetadata() throws Exception {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        MimeMessage mimeMessage = new MimeMessage(Session.getInstance(new Properties()));
        given(mailSender.createMimeMessage()).willReturn(mimeMessage);

        MailDeliveryProperties mailDeliveryProperties = new MailDeliveryProperties();
        mailDeliveryProperties.setFromEmail("auth@authapi.com");
        mailDeliveryProperties.setFromName("AuthApi Auth");
        mailDeliveryProperties.setReplyTo("support@authapi.com");

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.getEmailVerification().setVerificationUrlTemplate(
            "https://app.authapi.com/verify-email?token={token}"
        );

        SmtpAuthEmailSender sender = new SmtpAuthEmailSender(mailSender, mailDeliveryProperties, securityProperties);
        sender.sendEmailVerification(
            user("thomas@example.com", "Thomas Serna"),
            "token-123",
            Instant.parse("2026-04-10T12:30:00Z")
        );

        verify(mailSender).send(mimeMessage);
        String rawMessage = rawMessage(mimeMessage);

        assertThat(mimeMessage.getSubject()).isEqualTo("Verifica tu correo en AuthApi");
        assertThat(rawMessage).contains("https://app.authapi.com/verify-email?token=token-123");
        assertThat(rawMessage).contains("auth@authapi.com");
        assertThat(rawMessage).contains("Reply-To: support@authapi.com");
    }

    @Test
    void passwordResetEmailsShouldIncludeResetLink() throws Exception {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        MimeMessage mimeMessage = new MimeMessage(Session.getInstance(new Properties()));
        given(mailSender.createMimeMessage()).willReturn(mimeMessage);

        MailDeliveryProperties mailDeliveryProperties = new MailDeliveryProperties();
        mailDeliveryProperties.setFromEmail("auth@authapi.com");
        mailDeliveryProperties.setFromName("AuthApi Auth");

        SmtpAuthEmailSender sender = new SmtpAuthEmailSender(mailSender, mailDeliveryProperties, new SecurityProperties());
        sender.sendPasswordReset(
            user("thomas@example.com", "Thomas Serna"),
            "https://app.authapi.com/reset-password?token=encoded-token",
            Instant.parse("2026-04-10T12:30:00Z")
        );

        verify(mailSender).send(mimeMessage);
        String rawMessage = rawMessage(mimeMessage);

        assertThat(mimeMessage.getSubject()).isEqualTo("Restablece tu contrasena de AuthApi");
        assertThat(rawMessage).contains("https://app.authapi.com/reset-password?token=encoded-token");
        assertThat(rawMessage).contains("Thomas Serna");
    }

    private User user(String email, String fullName) {
        User user = new User();
        user.setEmail(email);
        user.setFullName(fullName);
        return user;
    }

    private String rawMessage(MimeMessage mimeMessage) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        mimeMessage.writeTo(outputStream);
        return outputStream.toString(StandardCharsets.UTF_8);
    }
}
