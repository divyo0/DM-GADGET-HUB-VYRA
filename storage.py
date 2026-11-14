"""Server-side SQLite storage and tenant-isolated records for VYRA Risk OS."""
from __future__ import annotations
import sqlite3, os, secrets, hashlib, json, random
from datetime import datetime,timezone,timedelta
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
ROOT=Path(__file__).resolve().parent
DB_DIR=ROOT/'private_data';DB_DIR.mkdir(exist_ok=True)
DB=DB_DIR/'vyra.sqlite3'
PH=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=2)
OWNER_EMAIL=os.getenv('OWNER_EMAIL','divymathur12345678901@gmail.com').strip().lower()

def now():return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
def epoch():return int(datetime.now(timezone.utc).timestamp())
def expiry(hours=1):return (datetime.now(timezone.utc)+timedelta(hours=hours)).replace(microsecond=0).isoformat()
def digest(token):return hashlib.sha256(token.encode('utf-8')).hexdigest()
def connect():
    db=sqlite3.connect(DB,timeout=15)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=10000')
    return db

def init():
    with connect() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS orgs(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,status TEXT DEFAULT 'ACTIVE',is_demo INTEGER DEFAULT 0,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,display_name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL,org_id INTEGER NOT NULL,active INTEGER DEFAULT 1,created_at TEXT NOT NULL,last_login TEXT, FOREIGN KEY(org_id) REFERENCES orgs(id));
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS challenges(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,code_hash TEXT NOT NULL,expires INTEGER NOT NULL,tries INTEGER DEFAULT 0,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS invites(token_hash TEXT PRIMARY KEY,email TEXT NOT NULL,role TEXT NOT NULL,org_id INTEGER NOT NULL,created_by INTEGER NOT NULL,expires INTEGER NOT NULL,used INTEGER DEFAULT 0,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY,org_id INTEGER NOT NULL,external_id TEXT NOT NULL,ts TEXT NOT NULL,amount REAL NOT NULL,product TEXT NOT NULL,features TEXT NOT NULL,risk_score INTEGER NOT NULL,decision TEXT NOT NULL,model TEXT NOT NULL,reason_json TEXT NOT NULL,workflow TEXT DEFAULT 'NEW',fraud_label INTEGER,source TEXT NOT NULL,notes TEXT DEFAULT '',created_at TEXT NOT NULL,device_hash TEXT DEFAULT '',account_hash TEXT DEFAULT '',payment_status TEXT DEFAULT 'UNKNOWN',UNIQUE(org_id,external_id));
        CREATE INDEX IF NOT EXISTS idx_tx_org ON transactions(org_id,ts);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,org_id INTEGER NOT NULL,category TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,detail TEXT NOT NULL,status TEXT DEFAULT 'OPEN',created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS disputes(id INTEGER PRIMARY KEY,org_id INTEGER NOT NULL,case_ref TEXT NOT NULL,order_id TEXT NOT NULL,amount REAL NOT NULL,reason TEXT NOT NULL,due_date TEXT NOT NULL,status TEXT DEFAULT 'OPEN',evidence TEXT NOT NULL,notes TEXT DEFAULT '',created_at TEXT NOT NULL,UNIQUE(org_id,case_ref));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,org_id INTEGER,actor_id INTEGER,action TEXT NOT NULL,detail TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS api_keys(id INTEGER PRIMARY KEY,org_id INTEGER NOT NULL,owner_id INTEGER NOT NULL,name TEXT NOT NULL,key_hash TEXT UNIQUE NOT NULL,created_at TEXT NOT NULL,revoked INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS card_events(id INTEGER PRIMARY KEY,org_id INTEGER NOT NULL,ts TEXT NOT NULL,fingerprint TEXT NOT NULL,amount REAL NOT NULL,authorized INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_ev_org ON card_events(org_id,ts);
        ''')
        # Upgrade existing VYRA V2 databases without deleting merchant records.
        existing={x['name'] for x in c.execute('PRAGMA table_info(transactions)').fetchall()}
        for col,typ in [('device_hash',"TEXT DEFAULT ''"),('account_hash',"TEXT DEFAULT ''"),('payment_status',"TEXT DEFAULT 'UNKNOWN'")]:
            if col not in existing:c.execute(f'ALTER TABLE transactions ADD COLUMN {col} {typ}')
        c.execute('CREATE INDEX IF NOT EXISTS idx_tx_fingerprint ON transactions(org_id,device_hash,ts)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_tx_account ON transactions(org_id,account_hash,ts)')
        if not c.execute("SELECT 1 FROM orgs WHERE name='DM Headquarters'").fetchone():
            c.execute("INSERT INTO orgs(name,status,is_demo,created_at) VALUES('DM Headquarters','ACTIVE',0,?)",(now(),))
        if not c.execute("SELECT 1 FROM orgs WHERE name='Reviewer Sandbox'").fetchone():
            c.execute("INSERT INTO orgs(name,status,is_demo,created_at) VALUES('Reviewer Sandbox','ACTIVE',1,?)",(now(),))
    ensure_demo()

def create_owner(password,email=OWNER_EMAIL):
    if len(password)<12:raise ValueError('Owner password must contain at least 12 characters')
    init()
    with connect() as c:
        if c.execute("SELECT 1 FROM users WHERE role='owner'").fetchone():return False
        org=c.execute("SELECT id FROM orgs WHERE name='DM Headquarters'").fetchone()['id']
        c.execute('INSERT INTO users(email,display_name,password_hash,role,org_id,created_at) VALUES(?,?,?,?,?,?)',
                  (email.lower(),'Divy Mathur',PH.hash(password),'owner',org,now()))
    return True

def has_owner():
    with connect() as c:return c.execute("SELECT 1 FROM users WHERE role='owner'").fetchone() is not None

def make_demo_user():
    with connect() as c:
        org=c.execute('SELECT id FROM orgs WHERE is_demo=1').fetchone()['id']
        u=c.execute("SELECT id FROM users WHERE role='demo'").fetchone()
        if u:return u['id']
        # This identity is accessible only via the server's explicit /demo auth path.
        c.execute('INSERT INTO users(email,display_name,password_hash,role,org_id,created_at) VALUES(?,?,?,?,?,?)',
                  ('reviewer@vyra.invalid','Reviewer Sandbox',PH.hash(secrets.token_urlsafe(32)),'demo',org,now()))
        return c.execute("SELECT id FROM users WHERE role='demo'").fetchone()['id']

def audit(org_id,actor_id,action,detail):
    with connect() as c:c.execute('INSERT INTO audit(org_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)',
        (org_id,actor_id,action,str(detail)[:500],now()))

def ensure_demo():
    """Demo data inserted only into the explicitly isolated demo tenant."""
    from risk import evaluate
    with connect() as c:
        org=c.execute('SELECT id FROM orgs WHERE is_demo=1').fetchone()['id']
        if c.execute('SELECT 1 FROM transactions WHERE org_id=? LIMIT 1',(org,)).fetchone():return
    rng=random.Random(2668)
    with connect() as c:
        demo_org=c.execute('SELECT id FROM orgs WHERE is_demo=1').fetchone()['id']
        for i in range(270):
            d={'amount':max(200,round(rng.lognormvariate(10.2,.55))),
               'new_address':rng.random()<.32,'new_device':rng.random()<.21,
               'recent_address_change':rng.random()<.08,'failed_logins':rng.choice([0,0,0,1,2,4]),
               'attempt_velocity':rng.choice([1,1,2,3,6]),'account_new':rng.random()<.19,
               'odd_hour':rng.random()<.2,'proxy_signal':rng.random()<.08,
               'declines_1h':rng.choice([0,0,1,3]),'shipping_billing_mismatch':rng.random()<.1}
            r=evaluate(d) # baseline model only
            ts=(datetime.now(timezone.utc)-timedelta(hours=270-i)).replace(microsecond=0).isoformat()
            c.execute('INSERT INTO transactions(org_id,external_id,ts,amount,product,features,risk_score,decision,model,reason_json,source,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                (demo_org,f'DEMO-{10001+i}',ts,d['amount'],rng.choice(['Laptop Pro','Phone Ultra','Wireless Earbuds','Tablet']),
                 json.dumps(d),r['risk_score'],r['decision'],r['model_version'],json.dumps(r['reasons']), 'SYNTHETIC',now()))
        for j in range(3000):
            dt=(datetime.now(timezone.utc)-timedelta(days=1,hours=10)+timedelta(seconds=j*6)).replace(microsecond=0).isoformat()
            c.execute('INSERT INTO card_events(org_id,ts,fingerprint,amount,authorized) VALUES(?,?,?,?,?)',
                (demo_org,dt,f'FP-{j%37:02d}',1.0,int(rng.random()<.035)))
        for cat,sev,title,detail in [
            ('CARD_TESTING','CRITICAL','3,000 micro-payment attempts','Simulated ₹1 card testing burst across 37 device fingerprints.'),
            ('ACCOUNT_TAKEOVER','HIGH','Account takeover pattern','New device, multiple login failures and a sudden address change.'),
            ('SHIPPING','MEDIUM','High-value rerouted shipment','Laptop purchase with a last-minute delivery change.')]:
            c.execute('INSERT INTO alerts(org_id,category,severity,title,detail,created_at) VALUES(?,?,?,?,?,?)',(demo_org,cat,sev,title,detail,now()))
        for j,(ref,reason,amount) in enumerate([('DSP-301','Unauthorized transaction',48000),('DSP-302','Item not received',28500),('DSP-303','Credit not processed',32000)]):
            c.execute('INSERT INTO disputes(org_id,case_ref,order_id,amount,reason,due_date,status,evidence,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                (demo_org,ref,f'DEMO-{10011+j}',amount,reason,expiry(72),'OPEN',json.dumps({'receipt':'Not uploaded',
                 'authentication_log':'Pending','carrier_tracking':'Pending','customer_messages':'Pending'}),now()))
