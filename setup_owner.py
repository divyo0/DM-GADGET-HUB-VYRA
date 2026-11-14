import os,sys,getpass
from pathlib import Path
ROOT=Path(__file__).resolve().parent
for line in (ROOT/'.env').read_text().splitlines() if (ROOT/'.env').exists() else []:
    if '=' in line and not line.lstrip().startswith('#'):
        k,v=line.split('=',1);os.environ.setdefault(k.strip(),v.strip())
from storage import create_owner,has_owner,init,OWNER_EMAIL
init()
if has_owner():
    print('Owner account already exists. Launching normally.')
    sys.exit(0)
print('\n===============================================')
print(' DM - GADGET HUB / VYRA | FIRST-RUN SETUP')
print('===============================================')
print('Create your private owner password (12+ characters).')
print('Owner email:',OWNER_EMAIL)
print('Your password stays hashed in local SQLite, not source code.\n')
for attempt in range(3):
    pw=getpass.getpass('New owner password: ')
    again=getpass.getpass('Confirm password: ')
    if pw != again: print('Passwords did not match.');continue
    if len(pw)<12: print('Use at least 12 characters.');continue
    created=create_owner(pw)
    print('Owner account created.' if created else 'Owner already configured.')
    break
else:
    print('Setup incomplete. Run again to choose a password.');sys.exit(1)
