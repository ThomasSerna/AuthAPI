# AuthApi

Servicio unico de autenticacion en Spring Boot, extraido del trabajo de auth de Prepetud y simplificado para funcionar como una sola API publica.

## Que incluye

- Registro, login, refresh rotation y logout.
- Login federado con Google y Microsoft.
- Verificacion de email, forgot password y reset password.
- Cambio de password, cambio de email y reautenticacion sensible.
- MFA TOTP, auditoria de eventos de seguridad y proteccion antiabuso.
- Cookie `HttpOnly` para refresh token dentro del mismo servicio.
- Landing inicial vacia servida desde `GET /`.

## Estructura

```text
src/
  main/
  test/
```

## Variables de entorno

La plantilla base vive en `.env.example`.

## Arranque local

```powershell
.\gradlew.bat bootRun
```

## Pruebas

```powershell
.\gradlew.bat test
```
