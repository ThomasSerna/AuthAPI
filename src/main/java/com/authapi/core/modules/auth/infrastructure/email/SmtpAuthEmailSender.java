package com.authapi.core.modules.auth.infrastructure.email;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import com.authapi.core.common.config.MailDeliveryProperties;
import com.authapi.core.common.config.SecurityProperties;
import com.authapi.core.modules.auth.domain.port.PasswordResetEmailSender;
import com.authapi.core.modules.auth.domain.port.VerificationEmailSender;
import com.authapi.core.modules.user.domain.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.util.StringUtils;

public class SmtpAuthEmailSender implements VerificationEmailSender, PasswordResetEmailSender {

    private static final DateTimeFormatter EXPIRY_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'")
        .withZone(ZoneOffset.UTC);

    private final JavaMailSender javaMailSender;

    private final MailDeliveryProperties mailDeliveryProperties;

    private final SecurityProperties securityProperties;

    public SmtpAuthEmailSender(
        JavaMailSender javaMailSender,
        MailDeliveryProperties mailDeliveryProperties,
        SecurityProperties securityProperties
    ) {
        this.javaMailSender = javaMailSender;
        this.mailDeliveryProperties = mailDeliveryProperties;
        this.securityProperties = securityProperties;
    }

    @Override
    public void sendEmailVerification(User user, String rawToken, Instant expiresAt) {
        String verificationUrl = buildActionUrl(
            securityProperties.getEmailVerification().getVerificationUrlTemplate(),
            rawToken
        );
        sendEmail(
            user.getEmail(),
            "Verifica tu correo en AuthApi",
            buildVerificationText(user, verificationUrl, expiresAt),
            buildVerificationHtml(user, verificationUrl, expiresAt)
        );
    }

    @Override
    public void sendPasswordReset(User user, String resetUrl, Instant expiresAt) {
        sendEmail(
            user.getEmail(),
            "Restablece tu contrasena de AuthApi",
            buildPasswordResetText(user, resetUrl, expiresAt),
            buildPasswordResetHtml(user, resetUrl, expiresAt)
        );
    }

    private void sendEmail(String to, String subject, String plainText, String htmlText) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, StandardCharsets.UTF_8.name());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setFrom(mailDeliveryProperties.getFromEmail(), mailDeliveryProperties.getFromName());
            if (StringUtils.hasText(mailDeliveryProperties.getReplyTo())) {
                helper.setReplyTo(mailDeliveryProperties.getReplyTo());
            }
            helper.setText(plainText, htmlText);
            javaMailSender.send(mimeMessage);
        } catch (MailException | MessagingException | UnsupportedEncodingException exception) {
            throw new IllegalStateException("Failed to deliver authentication email.", exception);
        }
    }

    private String buildActionUrl(String template, String rawToken) {
        String encodedToken = URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
        if (!StringUtils.hasText(template)) {
            return encodedToken;
        }
        if (template.contains("{token}")) {
            return template.replace("{token}", encodedToken);
        }
        return template.contains("?")
            ? template + "&token=" + encodedToken
            : template + "?token=" + encodedToken;
    }

    private String buildVerificationText(User user, String verificationUrl, Instant expiresAt) {
        return """
            Hola %s,

            Gracias por crear tu cuenta en AuthApi.

            Verifica tu correo desde este enlace:
            %s

            Este enlace vence el %s.

            Si no creaste esta cuenta, puedes ignorar este mensaje.
            """.formatted(resolveRecipientName(user), verificationUrl, formatExpiry(expiresAt));
    }

    private String buildVerificationHtml(User user, String verificationUrl, Instant expiresAt) {
        return """
            <html>
              <body style="font-family: Arial, Helvetica, sans-serif; background: #f4efe6; color: #1f2937; padding: 24px;">
                <div style="max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 20px; padding: 32px; border: 1px solid #e5dccf;">
                  <p style="margin: 0 0 16px; font-size: 14px; letter-spacing: 0.08em; text-transform: uppercase; color: #8a5a2b;">AuthApi</p>
                  <h1 style="margin: 0 0 16px; font-size: 28px; line-height: 1.2;">Verifica tu correo</h1>
                  <p style="margin: 0 0 16px;">Hola %s, gracias por crear tu cuenta en AuthApi.</p>
                  <p style="margin: 0 0 24px;">Haz clic en el boton para confirmar tu correo y activar tu cuenta.</p>
                  <p style="margin: 0 0 24px;">
                    <a href="%s" style="display: inline-block; background: #c96f1a; color: #ffffff; text-decoration: none; padding: 14px 22px; border-radius: 999px; font-weight: 700;">
                      Verificar correo
                    </a>
                  </p>
                  <p style="margin: 0 0 12px; font-size: 14px; color: #4b5563;">Este enlace vence el %s.</p>
                  <p style="margin: 0; font-size: 13px; color: #6b7280;">Si no creaste esta cuenta, puedes ignorar este mensaje.</p>
                </div>
              </body>
            </html>
            """.formatted(escapeHtml(resolveRecipientName(user)), escapeHtml(verificationUrl), formatExpiry(expiresAt));
    }

    private String buildPasswordResetText(User user, String resetUrl, Instant expiresAt) {
        return """
            Hola %s,

            Recibimos una solicitud para restablecer tu contrasena de AuthApi.

            Usa este enlace para continuar:
            %s

            Este enlace vence el %s.

            Si no solicitaste este cambio, puedes ignorar este mensaje.
            """.formatted(resolveRecipientName(user), resetUrl, formatExpiry(expiresAt));
    }

    private String buildPasswordResetHtml(User user, String resetUrl, Instant expiresAt) {
        return """
            <html>
              <body style="font-family: Arial, Helvetica, sans-serif; background: #eef2ff; color: #1f2937; padding: 24px;">
                <div style="max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 20px; padding: 32px; border: 1px solid #dbe2ff;">
                  <p style="margin: 0 0 16px; font-size: 14px; letter-spacing: 0.08em; text-transform: uppercase; color: #3050c7;">AuthApi</p>
                  <h1 style="margin: 0 0 16px; font-size: 28px; line-height: 1.2;">Restablece tu contrasena</h1>
                  <p style="margin: 0 0 16px;">Hola %s, recibimos una solicitud para cambiar tu contrasena.</p>
                  <p style="margin: 0 0 24px;">Usa este boton para crear una nueva contrasena de forma segura.</p>
                  <p style="margin: 0 0 24px;">
                    <a href="%s" style="display: inline-block; background: #1d4ed8; color: #ffffff; text-decoration: none; padding: 14px 22px; border-radius: 999px; font-weight: 700;">
                      Restablecer contrasena
                    </a>
                  </p>
                  <p style="margin: 0 0 12px; font-size: 14px; color: #4b5563;">Este enlace vence el %s.</p>
                  <p style="margin: 0; font-size: 13px; color: #6b7280;">Si no solicitaste este cambio, puedes ignorar este mensaje.</p>
                </div>
              </body>
            </html>
            """.formatted(escapeHtml(resolveRecipientName(user)), escapeHtml(resetUrl), formatExpiry(expiresAt));
    }

    private String resolveRecipientName(User user) {
        return StringUtils.hasText(user.getFullName()) ? user.getFullName() : user.getEmail();
    }

    private String formatExpiry(Instant expiresAt) {
        return EXPIRY_FORMATTER.format(expiresAt);
    }

    private String escapeHtml(String value) {
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }
}
