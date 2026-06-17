# Keycloak SAML Research Stack

This folder contains a minimal Keycloak stack for authorized ChatGPT SSO testing.

## Start locally

```powershell
Copy-Item .env.example .env
docker compose up -d
```

Open:

```text
http://localhost:8080
```

Localhost is enough for learning Keycloak, but ChatGPT SSO requires a public HTTPS
URL that OpenAI can redirect to and fetch metadata from.

## Configure ChatGPT SAML

1. In ChatGPT workspace settings, start the SSO setup wizard.
2. Verify your domain first.
3. Keep SSO optional during testing.
4. Copy the OpenAI Entity ID and ACS URL into `.env`.
5. Create the Keycloak realm and SAML client following `docs/sso/chatgpt-keycloak-saml.md`.
6. Upload Keycloak metadata back into the ChatGPT SSO wizard.

## Current local machine note

On Windows, this stack requires Docker Desktop or another Docker-compatible
runtime. If Docker is unavailable, deploy the same compose file on a Linux host
and set `KEYCLOAK_HOSTNAME` to the public HTTPS URL.
