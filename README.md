# Codex Referral Risk Research

This repository contains research tooling for studying SSO-based workspace referral flows, invite quota behavior, token lifecycle handling, and activation telemetry patterns in a controlled anti-fraud research setting.

The project is intended to help security and risk teams reproduce referral-flow edge cases, measure concurrency behavior, and evaluate where abuse-resistant controls should be enforced.

## Companion Repository

This repository is companion tooling for:

https://github.com/Tyxy-R/chatgpt-sso-keycloak

Use this project after the Keycloak SAML IdP is deployed and the target email domain is verified in the OpenAI Workspace.

## Research Focus

- SSO account creation paths in OAuth-based product onboarding.
- Workspace referral quota enforcement under concurrent invitation attempts.
- Differences between user-level and workspace-level referral limits.
- Token refresh and account activation behavior after referral acceptance.
- Batch-flow observability for fraud-risk analysis and control validation.

## Repository Contents

- `codex_protocol_login.py`  
  Direct Codex OAuth + SSO login flow. Supports single-account and CSV batch modes.

- `codex_invitation_helper.py`  
  Single-account referral quota probing and invite request helper.

- `codex_invitation_batch.py`  
  Concurrent seed-account invitation runner for quota and race-condition research.

- `codex_activation_helper.py`  
  Single-account protocol activation simulator.

- `codex_activation_batch.py`  
  Concurrent activation runner for invited-account research.

- `sentinel.py`, `sentinel_quickjs.py`, `openai_sentinel_quickjs.js`  
  Sentinel token generation helpers used by the login flow.

- `codex_sso_login.py`  
  Browser-based fallback login helper.

## Data Safety

Runtime data is intentionally excluded from git. Do not commit:

- account auth files
- access tokens
- refresh tokens
- id tokens
- account IDs
- real email/password CSV files
- invite result exports
- local logs

The `.gitignore` blocks common runtime directories and sensitive file patterns such as:

- `accounts/`
- `runs/`
- `*.csv`
- `*auth*.json`
- `.venv/`
- `*.log`

Only sanitized examples should be committed under `examples/`.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Example Research Workflow

Create a local CSV in the format shown by `examples/accounts.example.csv`:

```text
user1@example.com,YourPassword
user2@example.com,YourPassword
```

Log in seed accounts:

```bash
.venv/bin/python codex_protocol_login.py \
  --csv runs/example/seed_accounts.csv \
  --out-dir runs/example/seeds \
  --proxy http://127.0.0.1:PORT \
  --concurrency 10 \
  --retries 2 \
  --skip-existing
```

Probe and send referral invites from seed accounts:

```bash
.venv/bin/python codex_invitation_batch.py \
  --auth-dir runs/example/seeds \
  --domain example.com \
  --per-account 5 \
  --proxy http://127.0.0.1:PORT \
  --save-back \
  --out runs/example/invite_results.json
```

Extract only successfully invited emails:

```bash
jq -r '.[].invites[]?.email | . + ",YourPassword"' \
  runs/example/invite_results.json > runs/example/invitee_accounts.csv
```

Log in invited accounts:

```bash
.venv/bin/python codex_protocol_login.py \
  --csv runs/example/invitee_accounts.csv \
  --out-dir runs/example/invitees \
  --proxy http://127.0.0.1:PORT \
  --concurrency 10 \
  --retries 2 \
  --skip-existing
```

Run activation telemetry simulation:

```bash
.venv/bin/python codex_activation_batch.py \
  --auth-dir runs/example/invitees \
  --proxy http://127.0.0.1:PORT \
  --save-back
```

## Notes for Researchers

- Treat all generated auth files and CSVs as sensitive.
- Use isolated research tenants and domains.
- Validate results from server responses, not only from locally generated inputs.
- For invite analysis, count only `invites[].email` entries returned by the service.
- Keep raw artifacts under ignored runtime directories such as `runs/`.

## License

MIT License. See [LICENSE](LICENSE).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Tyxy-R/codex-referral-risk-research&type=Date)](https://www.star-history.com/#Tyxy-R/codex-referral-risk-research&Date)
