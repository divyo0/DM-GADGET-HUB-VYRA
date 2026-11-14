# DM – GADGET HUB · VYRA Risk OS 2.0

**Owner and creator:** Divy Mathur  
**Authorized owner email:** divymathur12345678901@gmail.com  
**Product:** Multi-user fraud-risk intelligence, investigations, and internal chargeback operations  
**Project:** Payomatix Fintech Fundamentals Capstone — GadgetHub fraud & chargebacks

## What this application actually does

VYRA is a locally runnable, full-stack fintech risk-operations **prototype**. It is more than a static dashboard. The Python backend runs a scikit-learn Histogram Gradient Boosting classifier plus transparent policy rules on actual transaction metadata provided by a merchant through CSV upload, manual analysis, or API ingestion. It writes risk results to SQLite, opens alerts for high-risk orders, supports analyst review and fraud labelling, and maintains a dispute-case workflow and audit history.

It is **not connected to banks, payment gateways, Google Sign-In, VisaNet, customer accounts, or courier systems**. It cannot actually authorize/decline payments, freeze external accounts, or submit disputes to card networks. Merchant integration requires an approved gateway/API connection, a secure deployment, and further regulatory/security review. The initial classifier is trained on **synthetic** data; its synthetic evaluation is NOT evidence of real-world accuracy.

## Install and run on Windows

Requirements: Windows 10/11; Python **3.12 recommended** (3.11 also supported); Internet access during first installation for `pip` dependencies. Roughly 1 GB free space recommended for Python and the environment.

1. Extract `DM_GADGET_HUB_VYRA_V2.zip` to an ordinary folder. Do not execute inside the ZIP.
2. Double-click **`run.bat`**. It creates `.venv`, installs requirements, and runs the first-time owner wizard.
3. When asked, choose a **new private owner password with at least 12 characters**. Owner email is preset to `divymathur12345678901@gmail.com`; the password is **not shipped** inside the ZIP.
4. A browser opens to **http://127.0.0.1:8765**. If it opens before the server has finished starting, refresh.
5. Log in with owner email and the password you just created.
6. From the sidebar select **Owner control**, create a merchant organization, and issue a private invitation link to that partner.
7. Use **Integrations** to upload a CSV or create a scoped API key. Now the real partner workspace begins receiving and scoring records.
8. Keep the black terminal window open. Close with `Ctrl+C` to stop the server.

If Windows blocks a batch file, right-click it → Properties → Unblock only if you trust the project. Run in your own extracted folder. If Python is not installed, install it first from the official Python site. The script downloads Python packages; it does not silently install system-wide software or a large language model.

For macOS/Linux: `bash run.sh`.

## Accounts, access and separation

| Access | Can do | Cannot do |
|---|---|---|
| **Owner (Divy Mathur)** | Create/suspend organizations, invite/suspend users, revoke sessions, select active merchant workspace, manage data, models and API keys | Read passwords or payment credentials |
| **Partner Admin** | Import orders and work with their own organization's transactions, keys and labelled model | Inspect another merchant or change platform-wide accounts |
| **Fraud Analyst** | Score, import and investigate orders, manage alerts/disputes, label cases | Invite users, manage API keys or train org models |
| **Viewer** | Inspect organization data and creator details | Write, review, change, import or issue keys |
| **Reviewer Demo** | Open the *isolated, explicitly labelled* sandbox **only from the machine running the server**; explore fictional data | Access real organizations, owner control, live integrations, or other tenant data |

**No ordinary partner or owner account is preloaded with synthetic demo customers/orders.** New real organizations start with **zero** transactions. The demo user signs in through a separate explicit button only. The admin organization list excludes the demo tenant.

## What each module is for

1. **Command overview** — active alerts, volume and decision mix for one organization; never substitute demo metrics for real metrics.
2. **Transaction ledger** — searchable records; investigate a transaction, add notes, update status, label confirmed fraud/legitimate outcomes.
3. **Risk intelligence** — enter permitted order features, score with actual backend model, see reasons, save transaction if required.
4. **Threat watch** — detect micro-payment risk via upstream and server-derived velocity; investigate, acknowledge and resolve alerts.
5. **Dispute desk** — create dispute cases, track response deadlines, record evidence references, change internal case status, export evidence JSON.
6. **Model studio** — see model provenance; after obtaining adequate verified labels, train a per-organization supervised classifier with time-based holdout metrics.
7. **Integrations** — export CSV template, import up to 5,000 rows/5 MB per file, issue/revoke organization-scoped API keys, and ingest JSON transactions.
8. **Identity & About** — profile, password change, creator name/email for all accounts; SMTP passwords and other private server configurations are NOT shown on this screen.
9. **Owner control** — only visible and usable by the owner: partner organizations, invites, suspend/reactivate, force sign-out, tenant inspection.

## Practical scenario: 3,000 ₹1 card tests

A merchant gateway sends records with `transaction_id`, `amount`, opaque `device_ref`, `payment_status` and optionally other risk features. VYRA stores an HMAC of device/account references (not the raw values). It derives each device's attempt velocity in the preceding 15 minutes and failure count in the preceding hour. Micro-payments with fast repeated attempts are escalated to the card-enumeration **DECLINE risk recommendation** and an alert is written. The merchant must separately implement throttling, security challenges and actual decline rules in its licensed gateway or edge tools.

## Practical scenario: account takeover

A gateway or identity service supplies `new_device=true`, `recent_address_change=true`, `failed_logins=4` and a ₹60,000 laptop purchase. The ATO rule floors the risk score at 88/100; an alert is opened when saved. An analyst can place the shipment on hold in the **merchant fulfilment system** and verify the customer. The VYRA UI records the analyst's status and notes; it does **not** itself change courier, bank, or identity-provider status.

## CSV schema and examples

Download the official header-only template from **Integrations → CSV schema**. Minimum headers:

```csv
transaction_id,amount
SHOP-2001,28000
SHOP-2002,1
```

Recommended: `transaction_id,timestamp,amount,product,device_ref,account_ref,payment_status,new_address,new_device,recent_address_change,failed_logins,attempt_velocity,account_new,odd_hour,proxy_signal,declines_1h,shipping_billing_mismatch,fraud_label`.

- `device_ref` and `account_ref` must be **opaque pseudonymous references**, not personal details or card numbers; raw references are HMAC-hashed before storage.
- `payment_status` may be `UNKNOWN`, `AUTHORIZED`, `FAILED`, `DECLINED`, or `REFUNDED`.
- Boolean values may be `true/false`, `yes/no`, or `1/0`.
- `fraud_label` is optional: blank, `0` verified legitimate, or `1` confirmed fraud. Only use reviewed labels.
- Fields named PAN, CVV, card_number, bank_account and similar are actively rejected. Do not submit raw credentials in *any* field.
- Import is per-organization; duplicate `transaction_id` values are skipped with row-level feedback.

### API example

In the **Integrations** page, an owner/partner admin can issue a scoped key. It is shown **once**, stored hashed server-side, and may be revoked.

```bash
curl -X POST http://127.0.0.1:8765/api/ingest \
  -H "X-API-Key: YOUR_PRIVATE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"transaction_id":"SHOP-350","amount":1,"product":"Mobile","device_ref":"opaque-device-47","payment_status":"DECLINED"}'
```

This is a **local testing** endpoint. Use HTTPS and a reviewed webhook authentication design in any hosted deployment. Never send this API secret in client-side JavaScript. Retrying the same `transaction_id` returns a duplicate response instead of writing duplicate records.

## Login and Gmail code verification — actual behaviour

**First start:** secure password login works. The UI clearly says **Email OTP not configured** until you configure SMTP. The app NEVER claims a real OTP was sent without SMTP credentials.

To enable genuine email OTP:

1. Open `SETUP_GMAIL_OTP.md` in this project.
2. Use a Google account with 2-Step Verification and App Password support, or an appropriate service account/provider.
3. Configure SMTP in the **local `.env` file only**, not `.env.example`, `app.py`, or the uploaded ZIP.
4. Restart `run.bat`. After password authentication, VYRA sends a six-digit code to that registered account address, which must be entered within 10 minutes.

This is **email OTP via Gmail SMTP**, not “Sign in with Google” OAuth. For remote production use, prefer a managed authentication provider with proper multi-factor authentication, HTTPS and organization policies.

## Model facts and honesty

- **Baseline:** scikit-learn `HistGradientBoostingClassifier`, trained on 4,800 random synthetic, labelled examples (80/20 chronological split of synthetic generation sequence). It uses 11 numeric/binary risk features.
- **Risk score:** `round(0.72 * rule_points_capped + 0.28 * model_probability * 100)` then protective overrides.
- **Policy bands:** 0–24 approve; 25–49 challenge; 50–74 manual review; 75–100 decline. All are **merchant design proposals**, not official card-network score thresholds.
- **Safeguards:** ₹1–₹5 + ≥10 short-window attempts → score ≥96; new device + recent address change + ≥3 failed logins → score ≥88; ≥25 attempts + ≥10 declines → score ≥95.
- **Merchant retrain:** Requires at least 100 labelled records, including 15 fraud and 35 legitimate; makes a time-ordered 80/20 split and persists the new tenant model. Synthetic metrics are not proof the system can detect real fraud at scale. A real project also needs model calibration, feature drift checks, fairness and label-delay handling.

## Themes / new visual system

Use the appearance selector at top right to switch between **Midnight Mint**, **Cloud Blue**, **Lemon Atelier** (white/yellow), and **Arctic Signal** (blue/white/black). All themes use the same functional application, with a distinct VYRA identity rather than the earlier Sentinel-style dashboard.

## Tests

Run:

```bash
python -m pytest -q tests/test_system.py
```

`pytest` is required for this developer command (`python -m pip install pytest httpx`). It is intentionally not required for runtime. At build time, **12 integration tests passed** (owner sign-in, CSRF, transactions, risk safeguards, tenant isolation, CSV validation, disputes, model, API ingestion and key revocation, card-testing velocity inference, partner session termination). Browser interaction checks also verified `×`, Escape, and backdrop modal dismissal, and risk preset input persistence.

## Folder map

```text
DM_GADGET_HUB_VYRA_V2/
  run.bat, run.sh           Startup, virtual environment and pip installation
  setup_owner.py            First-run private owner password wizard
  app.py                    FastAPI backend, login, RBAC, orgs, APIs
  storage.py                SQLite models, audit, restricted demo data
  risk.py                   ML pipeline, risk rules, safeguards, retraining
  requirements.txt          Runtime packages
  static/index.html         Main application shell
  static/styles.css         Four-theme UI and responsive layout
  static/app.js             Working screens and dialogs
  tests/test_system.py      Automated backend/security checks
  SETUP_GMAIL_OTP.md        Email code setup
  SECURITY_AND_DEPLOY.md    Controls and secure deployment caveats
  CAPSTONE_REPORT.pdf       Full six-question academic report
  previews/                 Browser-checked interface previews
```

**Never upload:** `.env`, `.venv`, `private_data/`, `private_models/`, or plaintext secrets. An extracted folder creates a local SQLite file and an HMAC secret. These remain only on that computer until you intentionally make an authorized deployment.

**Summary:** This is a functional *local educational risk-operations product* with real account roles, persistence and ML inference. It is not production-ready payment security or independently validated fraud AI. Review for security, privacy, legal requirements, uptime, monitoring and regulatory compliance before any real customer deployment.
