# Keycloak Admin Checklist for ChatGPT SAML

Use this checklist after the OpenAI SSO wizard has shown the workspace-specific
SAML values.

## Realm

- Create realm: `chatgpt-research`.
- Set a public frontend URL if Keycloak is behind a reverse proxy.
- Require email on user profiles.
- Create one admin fallback user and one non-admin test user.

## Client

- Create client.
- Client type: `SAML`.
- Client ID: paste OpenAI `Entity ID` / `Audience URI`.
- Name: `ChatGPT SSO`.
- Enabled: `On`.

## Client URLs

- Valid redirect URIs: paste OpenAI `ACS URL`.
- Master SAML processing URL: paste OpenAI `ACS URL`.
- IDP-initiated SSO URL name: leave empty unless the OpenAI wizard asks for it.

## Client signing

- Force POST binding: `On`.
- Sign documents: `On`.
- Sign assertions: `On`.
- Signature algorithm: `RSA_SHA256`.
- SAML signature key name: `KEY_ID` or Keycloak default.
- Encrypt assertions: `Off`.
- Client signature required: `Off`, unless OpenAI provides an SP certificate.

## NameID and mappers

- Name ID format: `email`.
- Add mapper `email`:
  - Mapper type: `User Property`.
  - Property: `email`.
  - SAML Attribute Name: `email`.
  - SAML Attribute NameFormat: `Basic`.
- Add mapper `firstName`:
  - Property: `firstName`.
  - SAML Attribute Name: `firstName`.
- Add mapper `lastName`:
  - Property: `lastName`.
  - SAML Attribute Name: `lastName`.

## Keycloak metadata

Open:

```text
https://<keycloak-host>/realms/chatgpt-research/protocol/saml/descriptor
```

Save the XML and upload it to the ChatGPT SSO wizard, or copy the IdP SSO URL
and signing certificate if the wizard asks for manual fields.

## Test order

1. Test Keycloak login directly.
2. Test ChatGPT SSO with a non-admin user.
3. Test admin login fallback.
4. Keep SSO optional until both tests pass.
5. Record screenshots and metadata hash under an ignored `runs/` folder.
