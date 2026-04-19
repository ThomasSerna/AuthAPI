# AuthAPI

A standalone Authentication service built with Spring Boot.

## 🚀 Key Features

- **Core Authentication:** Registration, Login, Refresh Token Rotation, and Logout.
- **Social Login:** Federated Login with Google and Microsoft.
- **Account Recovery:** Email Verification, Forgot Password, and Reset Password workflows.
- **Account Management:** Change Password, Change Email, and Sensitive Re-authentication requirements for critical actions.
- **Advanced Security:** 
  - Multi-Factor Authentication (MFA) via TOTP.
  - Security event auditing.
  - Anti-abuse protection mechanisms.
  - `HttpOnly` secure cookies used for refresh tokens.
- **Built-in Interactive Tester:** A visually stunning UI located at the root directory (`/`) to test every single API endpoint without the need for tools like Postman!

## 🛠️ Prerequisites

- Java 17 or higher
- Docker (for spinning up local database dependencies)

## ⚙️ Environment Configuration

The configuration template is located in `.env.example`. 

To get started, create a copy of `.env.example` and rename it to `.env`, then update the variables according to your security parameters and local environment.

## 🐳 Running Dependencies

A `docker-compose.yml` file is included to easily spin up the required database (MySQL) for local development:

```bash
# Starts the MySQL container in detached mode
docker-compose up -d
```

## 🏃‍♂️ Running the API

Once your `.env` file is ready and the Docker dependencies are running, you can launch the application:

**Windows:**
```powershell
.\gradlew.bat bootRun
```

**Mac/Linux:**
```bash
./gradlew bootRun
```

## 🧪 Built-in API Tester Platform

When the application finishes starting up, open your web browser and navigate to:

```text
http://localhost:8080/
```

You will find the custom **AuthAPI Tester** platform. This interactive UI allows you to:
- Test all available endpoints (categorized by Authentication, MFA, Social, etc.).
- Automatically manage your state (it saves the JWT `accessToken` when you login/register and injects it into the upcoming requests).
- Review nicely formatted JSON responses and HTTP status codes directly from the browser.

## ✅ Testing

To execute the test suite, run:

**Windows:**
```powershell
.\gradlew.bat test
```

**Mac/Linux:**
```bash
./gradlew test
```
