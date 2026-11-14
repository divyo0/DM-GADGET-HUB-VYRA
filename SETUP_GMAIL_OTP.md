# VYRA Risk OS — Genuine Gmail email-code setup

**Owner:** Divy Mathur · **Email:** divymathur12345678901@gmail.com

**Why the previous portal showed “To send genuine OTP…”:** It was displaying developer setup instructions in a normal user page. The old local project did not have real SMTP credentials, so it could not send email codes. This rebuild moves those instructions here, shows only the actual authentication status in the interface, and never pretends a code was sent.

## Setup steps (local server)

1. Open the extracted folder and start `run.bat` once to create `.env` from `.env.example`. Stop the server with `Ctrl+C`.
2. Enable **2-Step Verification** for the Gmail account that will send emails. If Google permits App Passwords for that account, create one dedicated to this application. Google may not offer App Passwords for some workspace/advanced protection accounts.
3. Edit the extracted **`.env` file** locally:

```ini
OWNER_EMAIL=divymathur12345678901@gmail.com
SMTP_USER=divymathur12345678901@gmail.com
SMTP_APP_PASSWORD=YOUR_16_CHARACTER_APP_PASSWORD
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
```

4. Save `.env`. Start `run.bat` again. The login page now honestly indicates that email OTP is active.
5. Enter your email and owner password. VYRA validates the password and sends a random six-digit one-time code through Gmail SMTP to the registered email.
6. Open Gmail, copy the code into VYRA, and sign in. Codes expire after **10 minutes** and have **5 failed attempts per challenge**. Request rate limit is **5/hour per user** (process-local).
7. Partner users with valid accounts receive their OTP at their own registered email address when SMTP is configured. Owner controls do not expose the sender's App Password.

**Troubleshooting:** Check the address, spam folder, Gmail security settings and SMTP connection. A provider rejection returns an error, **not** a false success message. `SMTP_APP_PASSWORD` is an app password, **never** your normal Google account password.

**Security:** NEVER publish `.env`, expose App Passwords in screenshots, send them to reviewers, or commit them to GitHub. Revoke the App Password if leaked. For an internet-facing service, a managed identity provider and OAuth/OIDC + MFA are safer than DIY SMTP OTP. Email codes are susceptible to mailbox compromise and phishing.

**This is not “Sign in with Google”.** It is a second verification factor delivered to Gmail after VYRA account-password authentication. True Google sign-in requires a separate Google OAuth project, verified redirect URIs, client credentials, state/PKCE and an approved production auth design.
