# Upload DM – GADGET HUB VYRA 2.0 to GitHub

## Recommended repository
- **Name:** `DM-GADGET-HUB-VYRA`
- **Description:** `Explainable fraud-risk intelligence and chargeback operations | Payomatix capstone | FastAPI + Python + multi-tenant dashboard`
- **Visibility:** Public for a portfolio, or Private while testing. Check that you want the creator email to be public before publishing.
- **Project:** Educational prototype only. Not a live payment processing / real-time fraud protection service.

## Safest route: Git from the extracted GitHub-ready folder
1. Install Git for Windows and sign in to GitHub. Extract this ZIP.
2. Open a terminal inside this folder (where `app.py`, `.gitignore`, and `README.md` are visible).
3. On GitHub create a NEW empty repository named `DM-GADGET-HUB-VYRA`. Leave 'Add README', '.gitignore', and 'License' unselected because this project already contains a README and `.gitignore`.
4. Run:

```bash
git init -b main
git add .
git status --short
git diff --cached --name-only
git commit -m "Initial release: VYRA Risk OS 2.0"
git remote add origin https://github.com/YOUR_USERNAME/DM-GADGET-HUB-VYRA.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your account username. Git may ask you to authenticate through your browser or credential manager. If Git asks for identity, run `git config --global user.name "Your GitHub Name"` and `git config --global user.email "your-github-email@example.com"`.

## Browser method (no Git commands)
1. On GitHub, create a new repository (`+` -> New repository); leave README/License blank.
2. Open it and click `uploading an existing file` or `Add file` -> `Upload files`.
3. Drag the **contents of this extracted clean folder**, preserving `static/`, `tests/`, `previews/`, into the browser. Do not upload ZIP as the project's only file.
4. Confirm that the list includes the actual code, not `.env` or any private databases.
5. Commit the upload. If hidden `.gitignore` wasn't added by your browser, add it separately using `Add file` -> `Create new file` and copy the contents of `.gitignore`.

## Never publish
`.env`, `.venv/`, `private_data/`, `private_models/`, real transaction records, personal customer data, or credentials. A `.gitignore` does not remove secrets that were already committed, and browser uploads should be manually checked.

## After upload
1. Verify the GitHub file tree contains `app.py`, `risk.py`, `storage.py`, `static/`, `tests/`, `requirements.txt` and `README.md`.
2. Copy your GitHub repository URL to the **GitHub repository** field in the Payomatix capstone submission.
3. The repository link alone does not deploy the software. For review, include Windows `run.bat` instructions and your separately submitted capstone ZIP/PDF.
4. Avoid exposing the owner dashboard publicly without independent security hardening. If you deploy a demo later, deploy an isolated instance with **synthetic-only data**.
