# VYRA — Security boundaries, limitations and deployment

## Local-only by default

The server binds to `127.0.0.1:8765`. This is intended for a laptop-based capstone and safe single-computer testing. No public URL is deployed by the files. Partners can be invited in the app, but an invite referencing `localhost` is only reachable from the machine hosting the app. For remote teams, use a hardened HTTPS-hosted deployment with managed identity and proper review; DO NOT just expose port 8765 to the public internet.

## Protections implemented for this prototype

- Argon2id password hashes, HttpOnly / SameSite session cookies, CSRF tokens for cookie-authenticated mutation endpoints.
- Random session tokens, 12-hour cookie life, server-side session invalidation, login attempts limited in process, OTP 10-minute expiration and 5 attempts when SMTP is configured.
- Owner-only organization/user creation and suspension; per-workspace server-side authorization for data queries; partner sessions revoked on suspension.
- Explicit, local-only reviewer demo login. Separate demo organization; owner/real partner workspaces are never populated from it.
- Hashed API keys; once-visible secrets can be revoked. Raw `device_ref` and `account_ref` pseudonymous references are HMAC-hashed in storage.
- CSV limits: 5 MB / 5,000 rows; card-secret column names rejected; JSON requests reject direct raw card credential fields.
- Exports are internal evidence records, not actual issuer/card-network submissions.
- Model training separated per organization; stored models are local, app-generated joblib artifacts. Never load untrusted model files.
- Audit records on key account and casework actions.

## Additional work REQUIRED before real deployment

1. HTTPS termination and secure cookies; managed identity (OIDC), policy-based MFA, recovery, mandatory email verification and SSO as needed.
2. Centralized rate limiting, an external persistent session store, robust secrets management, strong input schemas, continuous dependency and penetration testing.
3. Production database with encryption, backups, least-privilege service accounts, documented retention/deletion and tenant isolation tests.
4. Approved payment provider integration. No raw PAN, CVV, PIN, card security data or passwords; PCI DSS scope evaluation with a qualified professional.
5. DPDP and privacy-law analysis, consent/transparency, access/deletion requests and lawful processing; legal review for India and cross-border cases.
6. Proper incident management, idempotency and retry policies, signed gateway webhooks, message queue, tamper-evident audit logs, operational metrics and on-call procedures.
7. Evaluate against verified real fraud labels and delayed outcomes; handle class imbalance, calibration, false positives, bias, drift, attack adaptation, model ownership and human appeals.
8. Do not treat scoring as payment authorization, bank account freezing, real cardholder authentication, or a guarantee that any chargeback is winnable.
9. Owner control: invite, suspend, revoke session; cannot see passwords. In a hosted deployment, separate platform root capabilities from merchant analysts using reviewed authorization policies.
10. For any public reviewer demo, deploy a **separate dedicated environment containing only synthetic data** with no owner or merchant credentials, and follow a security review.

## Exact status

Educational **prototype**. Core service endpoints and modal interactions have automated/visual tests. No real SMTP email has been delivered from the owner's Gmail in this sandbox, because no App Password is stored in the project. No public hosting or external payments network integration has been performed. No "zero bugs" or production compliance warranty is possible.
