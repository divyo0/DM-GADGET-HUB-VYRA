import os
from storage import init, has_owner, create_owner

# Initialize database and application storage
init()

# Create admin account only on the first launch
if not has_owner():
    password = os.environ.get("OWNER_SETUP_PASSWORD", "")

    if len(password) < 12:
        raise SystemExit(
            "Set OWNER_SETUP_PASSWORD in Render Environment "
            "to a private password of at least 12 characters."
        )

    if create_owner(password):
        print("Owner account initialized successfully.")
else:
    print("Existing owner account found.")
