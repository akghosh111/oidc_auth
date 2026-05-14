# OIDC Auth Server

A production-ready OpenID Connect (OIDC) authentication server built with Node.js, Express, and Drizzle ORM. This server provides a centralized authentication service supporting the Authorization Code flow for third-party application integration.

## Features

- **OIDC Discovery**: Implementation of `.well-known/openid-configuration`.
- **Authorization Code Flow**: Secure exchange of authorization codes for access and refresh tokens.
- **PKCE (Proof Key for Code Exchange)**: Enhanced security for public and private clients, protecting against authorization code injection.
- **Refresh Token Rotation**: Automatic token replacement and reuse detection to mitigate session hijacking risks.
- **Application Management**: Administrative interface for registering third-party applications.
- **Dynamic Context**: Authentication and registration screens that adapt based on the requesting application.
- **JWT Issuance**: RSA256 signed tokens for secure identity propagation.
- **User Management**: Integrated sign-in and sign-up processes with salt-based password hashing.

## Architecture & Flow

### System Architecture

- **Runtime**: Node.js with Express.
- **Database**: PostgreSQL with Drizzle ORM.
- **Cryptography**: `node-jose` for JWKS and `jsonwebtoken` for signing.
- **Frontend**: Vanilla JavaScript and CSS served as static assets.

```mermaid
graph TD
    User((User))
    App[Third-Party App]
    AuthServer[Auth Server (Express)]
    DB[(PostgreSQL)]
    Cert[RSA Keys (cert/)]

    User <--> App
    App <--> AuthServer
    AuthServer <--> DB
    AuthServer <--> Cert
    
    subgraph "Auth Server (Node.js)"
        Endpoints[OIDC Endpoints]
        Logic[Auth & Token Logic]
        Drizzle[Drizzle ORM]
    end
```

### Authorization & Token Flow (with PKCE & Rotation)

```mermaid
sequenceDiagram
    participant User
    participant App as Third-Party App
    participant Auth as Auth Server
    participant DB as Database

    Note over User, Auth: 1. Authorization Request (PKCE)
    App->>Auth: GET /o/authenticate (client_id, code_challenge, ...)
    Auth-->>User: Sign-in / Sign-up Page
    User->>Auth: POST /o/authenticate/sign-in (creds, code_challenge)
    Auth->>DB: Verify User & Store Auth Code + Challenge
    Auth-->>App: 302 Redirect (code)

    Note over App, Auth: 2. Token Exchange
    App->>Auth: POST /o/tokeninfo (code, code_verifier, client_secret)
    Auth->>DB: Validate Code, Verifier & Application
    DB-->>Auth: Valid
    Auth->>DB: Store Refresh Token Hash
    Auth-->>App: 200 OK (access_token, refresh_token)

    Note over App, Auth: 3. Refresh Token Rotation
    App->>Auth: POST /o/tokeninfo (grant_type=refresh_token, refresh_token)
    Auth->>DB: Validate Refresh Token (not consumed/revoked)
    Auth->>DB: Mark old token consumed, Issue new Refresh Token
    Auth-->>App: 200 OK (access_token, new_refresh_token)

    Note over App, Auth: 4. Reuse Detection (Security)
    App->>Auth: POST /o/tokeninfo (grant_type=refresh_token, OLD_refresh_token)
    Auth->>DB: Detect reuse (consumedAt is set)
    Auth->>DB: Revoke all tokens for User/App session
    Auth-->>App: 401 Unauthorized (Reuse detected)
```

## Prerequisites

- Node.js (v18 or higher)
- PostgreSQL Database
- npm or yarn

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd oidc_auth
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   Create a `.env` file in the root directory with the following variables:
   ```env
   DATABASE_URL=postgres://user:password@localhost:5432/oidc_auth
   PORT=8000
   ```

4. Generate RSA Key Pair:
   The server requires RSA keys for signing and verifying JWTs. Run the provided key generator:
   ```bash
   node keygen.js
   ```
   This will create a `cert/` directory with `private.key` and `public.key`.

## Database Setup

The project uses Drizzle ORM for database management.

1. Generate migrations:
   ```bash
   npm run db:generate
   ```

2. Apply migrations:
   ```bash
   npm run db:migrate
   ```

## Running the Server

Development mode with hot-reloading:
```bash
npm run dev
```

The server will be available at `http://localhost:8000`.

## Administrative Workflow

### Registering an Application

1. Navigate to `http://localhost:8000/admin`.
2. Provide the Application Display Name, Application URL, and Redirect URI.
3. Upon registration, the system will generate a `client_id` and `client_secret`.
4. Store the `client_secret` securely; it is required for token exchange.

## OIDC Integration Flow

### 1. Authorization Request

Redirect users to the authentication endpoint:
`GET /o/authenticate?client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>&state=<STATE>`

### 2. User Authentication

The user signs in or creates an account. The UI will display the name of the requesting application.

### 3. Code Issuance

Upon successful authentication, the server redirects to the specified `redirect_uri` with a short-lived authorization code:
`HTTP 302 Redirect: <REDIRECT_URI>?code=<AUTH_CODE>&state=<STATE>`

### 4. Token Exchange

The third-party application exchanges the code for tokens:
`POST /o/tokeninfo`
Payload:
```json
{
  "code": "<AUTH_CODE>",
  "client_secret": "<CLIENT_SECRET>"
}
```

Response:
```json
{
  "access_token": "<JWT>",
  "refresh_token": "<TOKEN>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## API Reference

### OIDC Metadata
- `GET /.well-known/openid-configuration`: Returns OIDC server metadata.
- `GET /.well-known/jwks.json`: Returns public keys for JWT verification.

### Authentication
- `GET /o/authenticate`: Serves the sign-in page.
- `GET /o/signup`: Serves the registration page.
- `POST /o/authenticate/sign-in`: Handles user login.
- `POST /o/authenticate/sign-up`: Handles user registration.
- `GET /o/userinfo`: Returns authenticated user profile data (requires Bearer token).

### Internal
- `GET /o/application-info`: Fetches public metadata for a specific application.
- `GET /health`: System health check endpoint.
