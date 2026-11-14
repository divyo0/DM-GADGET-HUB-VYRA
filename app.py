"""DM - GADGET HUB | VYRA Risk OS. Local multi-tenant educational risk operations.
No real card authorization, issuer connections, verified fraud model or GDPR/PCI certification.
"""
from __future__ import annotations
import os, sys, json, csv, io, secrets, hashlib, hmac, smtplib, ssl, time, re, sqlite3, threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from email.message import EmailMessage
from urllib.parse import urlsplit
from argon2.exceptions import VerifyMismatchError, VerificationError


ROOT=Path(__file__).resolve().parent
if (ROOT/'.env').exists():
    for line in (ROOT/'.env').read_text(encoding='utf-8').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1);os.environ.setdefault(key.strip(),value.strip())

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Query
from fastapi.responses import JSONResponse,FileResponse,HTMLResponse,PlainTextResponse
from fastapi.staticfiles import StaticFiles
from storage import init,connect,now,epoch,expiry,digest,PH,OWNER_EMAIL,has_owner,make_demo_user,audit
from risk import evaluate,normalized,FEATURES,baseline,tenant_model,train_tenant

init()
app=FastAPI(title='VYRA Risk OS',version='2.0.0',docs_url='/api/developer/docs',redoc_url=None,openapi_url='/api/developer/openapi.json')
app.mount('/assets',StaticFiles(directory=ROOT/'static'),name='assets')
SMTP_USER=os.getenv('SMTP_USER','').strip()
SMTP_PASSWORD=os.getenv('SMTP_APP_PASSWORD','').strip().replace(' ','')
SMTP_HOST=os.getenv('SMTP_HOST','smtp.gmail.com').strip()
SMTP_PORT=int(os.getenv('SMTP_PORT','465'))
SMTP_READY=bool(SMTP_USER and SMTP_PASSWORD)
DEMO=os.getenv('ENABLE_REVIEWER_DEMO','true').lower() in ('1','true','yes')
REVIEWER_ACCESS_CODE=os.getenv('REVIEWER_ACCESS_CODE','').strip()
SECURE_COOKIE=os.getenv('COOKIE_SECURE','false').lower() in ('1','true','yes')
ATTEMPTS=defaultdict(list)
LOCK=threading.Lock()


def fail(message='Unable to complete this request',status=400):raise HTTPException(status_code=status,detail=message)

def dto(row):return dict(row) if row else None

def limited(key,n,window):
    with LOCK:
        t=time.time()
        ATTEMPTS[key]=[x for x in ATTEMPTS[key] if x>t-window]
        if len(ATTEMPTS[key])>=n:return False
        ATTEMPTS[key].append(t);return True


def checked_json(reqdata,allowed=None):
    if not isinstance(reqdata,dict):fail('JSON object expected')
    if allowed and any(k not in allowed for k in reqdata):fail('Unexpected field provided')
    return reqdata

async def body_json(req:Request):
    if int(req.headers.get('content-length','0'))>50000:fail('Request too large',413)
    try:
        raw=await req.body()
        if len(raw)>50000:fail('Request too large',413)
        return checked_json(json.loads(raw))
    except (UnicodeDecodeError,ValueError):fail('Invalid JSON request')


def verified_user(req:Request):
    cookie=req.cookies.get('vyra_session','')
    if not cookie:return None
    with connect() as c:
        row=c.execute('''SELECT u.id,u.email,u.display_name,u.role,u.org_id,u.active,o.name AS org_name,o.is_demo,
                         o.status AS org_status,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id
                         JOIN orgs o ON u.org_id=o.id WHERE s.token_hash=? AND s.expires>?''',
                      (digest(cookie),epoch())).fetchone()
    if not row or row['active']!=1 or row['org_status']!='ACTIVE':return None
    return dict(row)

async def require_user(req:Request):
    u=verified_user(req)
    if not u:fail('Please sign in',401)
    return u

def check_csrf(req,u):
    if not hmac.compare_digest(req.headers.get('x-csrf-token',''),u['csrf']):fail('Invalid session token; refresh the page',403)
    origin=req.headers.get('origin','')
    if origin and urlsplit(origin).netloc!=req.headers.get('host',''):
        fail('Cross-origin changes are not allowed',403)

def require_role(u,*roles):
    if u['role'] not in roles:fail('This action requires a higher access role',403)

def org_for(u,workspace=None):
    if u['role']!='owner':return u['org_id']
    if workspace in ('',None):return u['org_id']
    try:org=int(workspace)
    except (ValueError,TypeError):fail('Invalid workspace')
    with connect() as c:row=c.execute('SELECT id,status,is_demo FROM orgs WHERE id=?',(org,)).fetchone()
    if not row or row['status']!='ACTIVE':fail('Workspace unavailable',404)
    if row['is_demo']:fail('Use the separate reviewer login for demonstration data',403)
    return org

def ensure_writable(u):
    if u['role'] not in ('owner','partner_admin','analyst','demo'):
        fail('Your account is read-only',403)

def audit_action(u,org,action,detail):audit(org,u['id'],action,detail)

def session_response(user_id,response):
    token=secrets.token_urlsafe(40);csrf=secrets.token_urlsafe(32)
    with connect() as c:
        c.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires,created_at) VALUES(?,?,?,?,?)',
                  (digest(token),user_id,csrf,epoch()+12*3600,now()))
        c.execute('UPDATE users SET last_login=? WHERE id=?',(now(),user_id))
    response.set_cookie('vyra_session',token,httponly=True,secure=SECURE_COOKIE,samesite='strict',max_age=12*3600,path='/')
    return response

def send_otp(address,code):
    if not SMTP_READY:fail('Email verification is not configured on the server',503)
    msg=EmailMessage()
    msg['From']=SMTP_USER;msg['To']=address
    msg['Subject']='VYRA Risk OS | Your verification code'
    msg.set_content(f'Your VYRA Risk OS sign-in code is: {code}\n\nValid for 10 minutes. Do not share this code.\nIf you did not request it, ignore this message.')
    with smtplib.SMTP_SSL(SMTP_HOST,SMTP_PORT,timeout=12,context=ssl.create_default_context()) as s:
        s.login(SMTP_USER,SMTP_PASSWORD);s.send_message(msg)

HASH_SALT_PATH=ROOT/'private_data'/'fingerprint_secret'
if not HASH_SALT_PATH.exists():
    HASH_SALT_PATH.write_bytes(secrets.token_bytes(32))
    try:HASH_SALT_PATH.chmod(0o600)
    except OSError:pass
FINGERPRINT_SECRET=HASH_SALT_PATH.read_bytes()

def opaque_hash(org,ref):
    val=str(ref or '').strip()
    if not val:return ''
    if len(val)>200:fail('Opaque reference is too long')
    return hmac.new(FINGERPRINT_SECRET,f'{org}|{val}'.encode(),hashlib.sha256).hexdigest()

def enriched_order(org,data):
    """Derive device velocity & recent declines, keeping raw device refs out of the DB."""
    order=parse_order(data)
    dh=opaque_hash(org,data.get('device_ref'))
    ah=opaque_hash(org,data.get('account_ref'))
    if dh:
        try:tx_time=datetime.fromisoformat(str(data.get('timestamp') or now()).replace('Z','+00:00'))
        except ValueError:tx_time=datetime.now(timezone.utc)
        if tx_time.tzinfo is None:tx_time=tx_time.replace(tzinfo=timezone.utc)
        earlier=(tx_time-timedelta(minutes=15)).isoformat()
        hour=(tx_time-timedelta(hours=1)).isoformat()
        with connect() as c:
            recent=c.execute('SELECT COUNT(*) FROM transactions WHERE org_id=? AND device_hash=? AND ts>=? AND ts<=?',
               (org,dh,earlier,tx_time.isoformat())).fetchone()[0]
            declines=c.execute("SELECT COUNT(*) FROM transactions WHERE org_id=? AND device_hash=? AND ts>=? AND ts<=? AND payment_status IN ('FAILED','DECLINED')",
               (org,dh,hour,tx_time.isoformat())).fetchone()[0]
            if ah:
                prior=c.execute('SELECT COUNT(*) FROM transactions WHERE org_id=? AND account_hash=?',(org,ah)).fetchone()[0]
                seen=c.execute('SELECT COUNT(*) FROM transactions WHERE org_id=? AND account_hash=? AND device_hash=?',(org,ah,dh)).fetchone()[0]
                if prior>0 and seen==0:order['new_device']=True
        order['attempt_velocity']=max(order['attempt_velocity'],recent+1)
        order['declines_1h']=max(order['declines_1h'],declines)
    return order,dh,ah

def parse_order(d):
    forbidden={'pan','card_number','cvv','cvc','expiry','full_card_number','card_cvv','password','bank_account','account_number','card_pin','pin_block'}
    if any(str(k).lower().strip() in forbidden for k in d):fail('Remove sensitive payment credentials from the request')
    if 'amount' not in d:fail('The amount field is required')
    try:n=normalized(d)
    except ValueError as e:fail(str(e))
    if n['amount']<=0:fail('Amount must be positive')
    return n


def save_order(org,u,data,source='MANUAL'):
    order,device_hash,account_hash=enriched_order(org,data)
    ext=str(data.get('transaction_id') or data.get('external_id') or 'TX-'+secrets.token_hex(5).upper()).strip()[:80]
    if not re.fullmatch(r'[\w\-.]+',ext):fail('Transaction ID allows letters, numbers, dash, underscore and dot')
    result=evaluate(order,org_id=org)
    product=str(data.get('product') or 'Electronics order')[:100]
    requested_ts=str(data.get('timestamp') or now())[:40]
    try:datetime.fromisoformat(requested_ts.replace('Z','+00:00'))
    except ValueError:fail('timestamp must be ISO-8601')
    payment_status=str(data.get('payment_status') or 'UNKNOWN').upper().strip()
    if payment_status not in ('UNKNOWN','AUTHORIZED','FAILED','DECLINED','REFUNDED'):
        fail('payment_status must be UNKNOWN, AUTHORIZED, FAILED, DECLINED or REFUNDED')
    label=data.get('fraud_label')
    if label not in (None,'','0','1',0,1):fail('fraud_label must be 0, 1 or blank')
    label=None if label in ('',None) else int(label)
    try:
        with connect() as c:
            cur=c.execute('''INSERT INTO transactions(org_id,external_id,ts,amount,product,features,risk_score,decision,model,reason_json,source,created_at,fraud_label,device_hash,account_hash,payment_status)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(org,ext,requested_ts,order['amount'],product,json.dumps(order),result['risk_score'],
                result['decision'],result['model_version'],json.dumps(result['reasons']+[
                    {'factor':g,'weight':'safeguard'} for g in result['guardrails']]),source,now(),label,device_hash,account_hash,payment_status))
            id_=cur.lastrowid
            if result['risk_score']>=75:
                category='CARD_TESTING' if order['amount']<=5 and order['attempt_velocity']>=10 else (
                         'ATO' if 'Account takeover safeguard' in result['guardrails'] else 'HIGH_RISK')
                c.execute('INSERT INTO alerts(org_id,category,severity,title,detail,created_at) VALUES(?,?,?,?,?,?)',
                          (org,category,'CRITICAL' if result['risk_score']>=90 else 'HIGH',
                           'High-risk order: '+ext,'Review flagged signals before fulfilment. Score: '+str(result['risk_score']),now()))
    except sqlite3.IntegrityError:fail('This transaction ID already exists in this workspace',409)
    audit(org,u['id'] if u else None,'ORDER_SCORED',ext+' '+result['decision'])
    return {'id':id_,'transaction_id':ext,**result}

@app.middleware('http')
async def headers(request,call_next):
    res=await call_next(request)
    res.headers['X-Content-Type-Options']='nosniff'
    res.headers['Referrer-Policy']='no-referrer'
    res.headers['X-Frame-Options']='DENY'
    res.headers['Cache-Control']='no-store'
    res.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    return res

@app.get('/')
def index():return FileResponse(ROOT/'static'/'index.html')

@app.get('/api/health')
def health():return {'service':'DM GADGET HUB / VYRA','ok':True,'version':'2.0.0','live_payments':False}

@app.get('/api/bootstrap')
def bootstrap():
    return {'service':'VYRA Risk OS','creator':'Divy Mathur','creator_email':OWNER_EMAIL,
        'owner_initialized':has_owner(),'demo_enabled':DEMO,'verification_mode':'EMAIL_OTP' if SMTP_READY else 'PASSWORD_ONLY',
        'model_type':'Histogram Gradient Boosting + rule guardrails'}

@app.post('/api/auth/login')
async def login(req:Request):
    d=await body_json(req);email=str(d.get('email','')).strip().lower()
    password=str(d.get('password',''))
    ip=req.client.host if req.client else 'unknown'
    if not limited('login:'+ip+':'+email,7,900):fail('Too many attempts. Please try later',429)
    with connect() as c:
        user=c.execute('''SELECT u.*,o.status org_status FROM users u JOIN orgs o ON u.org_id=o.id WHERE u.email=?''',(email,)).fetchone()
    try:
        if not user or user['role']=='demo' or user['active']==0 or user['org_status']!='ACTIVE':
            PH.verify(PH.hash('dummy-verification-workload'),password or 'bad')
            fail('Email or password is incorrect',401)
        PH.verify(user['password_hash'],password)
    except (VerifyMismatchError,VerificationError):fail('Email or password is incorrect',401)
    if not SMTP_READY:
        response=JSONResponse({'ok':True,'otp_required':False})
        audit(user['org_id'],user['id'],'LOGIN','Password authentication')
        return session_response(user['id'],response)
    if not limited('otp:'+str(user['id']),5,3600):fail('Too many email codes requested',429)
    code=''.join(str(secrets.randbelow(10)) for _ in range(6))
    challenge=secrets.token_urlsafe(32)
    # SHA256 with a fresh secret salt scoped to challenge, code never kept plaintext.
    codehash=digest(challenge+':'+code)
    with connect() as c:c.execute('INSERT INTO challenges(token_hash,user_id,code_hash,expires,created_at) VALUES(?,?,?,?,?)',
         (digest(challenge),user['id'],codehash,epoch()+600,now()))
    try:send_otp(email,code)
    except Exception:
        with connect() as c:c.execute('DELETE FROM challenges WHERE token_hash=?',(digest(challenge),))
        fail('Could not send email code. Verify SMTP configuration',503)
    return {'ok':True,'otp_required':True,'challenge':challenge,'masked_email':email[0:2]+'***@'+email.split('@')[-1]}

@app.post('/api/auth/verify')
async def verify(req:Request):
    d=await body_json(req);challenge=str(d.get('challenge',''));code=str(d.get('code',''))
    if not re.fullmatch(r'\d{6}',code):fail('A six-digit code is required')
    with connect() as c:
        row=c.execute('SELECT * FROM challenges WHERE token_hash=?',(digest(challenge),)).fetchone()
        if not row or row['expires']<epoch() or row['tries']>=5:fail('Verification code expired or invalid',401)
        c.execute('UPDATE challenges SET tries=tries+1 WHERE token_hash=?',(digest(challenge),))
        if not hmac.compare_digest(row['code_hash'],digest(challenge+':'+code)):fail('Invalid code',401)
        c.execute('DELETE FROM challenges WHERE token_hash=?',(digest(challenge),))
        user=c.execute('SELECT org_id,active FROM users WHERE id=?',(row['user_id'],)).fetchone()
        if not user or not user['active']:fail('Account unavailable',403)
    audit(user['org_id'],row['user_id'],'LOGIN','Verified email OTP')
    return session_response(row['user_id'],JSONResponse({'ok':True}))

@app.post('/api/auth/demo')
async def demo(req:Request):
    # Public access requires a server-side reviewer code; sandbox remains tenant-isolated.
    if not DEMO:fail('Reviewer sandbox is disabled',403)
    ip=req.client.host if req.client else 'unknown'
    if not limited('reviewer-demo:'+ip,8,900):
        fail('Too many reviewer login attempts. Try again later',429)
    if len(REVIEWER_ACCESS_CODE)<16:
        fail('Reviewer access is not configured; set a 16+ character access code',503)
    data=await body_json(req)
    submitted=str(data.get('code',''))
    if not hmac.compare_digest(submitted,REVIEWER_ACCESS_CODE):
        fail('Invalid reviewer access code',403)
    user_id=make_demo_user()
    audit(None,user_id,'DEMO_LOGIN','Access-code-protected isolated reviewer tenant')
    return session_response(user_id,JSONResponse({'ok':True}))

@app.get('/api/auth/invite/{token}')
def invite_info(token:str):
    with connect() as c:
        row=c.execute('''SELECT i.email,i.role,i.expires,i.used,o.name org_name,o.status org_status FROM invites i
           JOIN orgs o ON o.id=i.org_id WHERE i.token_hash=?''',(digest(token),)).fetchone()
    if not row or row['used'] or row['expires']<epoch() or row['org_status']!='ACTIVE':fail('Invite invalid or expired',404)
    return {'email':row['email'],'role':row['role'],'workspace':row['org_name']}

@app.post('/api/auth/activate')
async def activate(req:Request):
    d=await body_json(req);token=str(d.get('token',''));name=str(d.get('name','')).strip()[:80];password=str(d.get('password',''))
    if not 2<=len(name)<=80 or len(password)<12:fail('Display name and a password of 12+ characters are required')
    with connect() as c:
        invite=c.execute('SELECT * FROM invites WHERE token_hash=?',(digest(token),)).fetchone()
        if not invite or invite['used'] or invite['expires']<epoch():fail('Invite expired or already used',403)
        if c.execute('SELECT 1 FROM users WHERE email=?',(invite['email'],)).fetchone():fail('Email already has an account',409)
        c.execute('INSERT INTO users(email,display_name,password_hash,role,org_id,created_at) VALUES(?,?,?,?,?,?)',
              (invite['email'],name,PH.hash(password),invite['role'],invite['org_id'],now()))
        c.execute('UPDATE invites SET used=1 WHERE token_hash=?',(digest(token),))
    audit(invite['org_id'],None,'ACCOUNT_ACTIVATED',invite['email'])
    return {'ok':True,'message':'Account created. Sign in with your email and password.'}

@app.get('/api/me')
async def me(u=Depends(require_user)):
    return {'id':u['id'],'email':u['email'],'name':u['display_name'],'role':u['role'],
            'org_id':u['org_id'],'org_name':u['org_name'],'is_demo':bool(u['is_demo']),
            'csrf':u['csrf'],'otp_enabled':SMTP_READY}

@app.post('/api/auth/logout')
async def logout(req:Request,u=Depends(require_user)):
    check_csrf(req,u)
    token=req.cookies.get('vyra_session','')
    with connect() as c:c.execute('DELETE FROM sessions WHERE token_hash=?',(digest(token),))
    res=JSONResponse({'ok':True});res.delete_cookie('vyra_session',path='/');return res

@app.post('/api/auth/password')
async def password_change(req:Request,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner','partner_admin','analyst','viewer')
    d=await body_json(req);old=str(d.get('old',''));new=str(d.get('new',''))
    if len(new)<12:fail('Password must have at least 12 characters')
    with connect() as c:
        oldhash=c.execute('SELECT password_hash FROM users WHERE id=?',(u['id'],)).fetchone()['password_hash']
        try:PH.verify(oldhash,old)
        except (VerifyMismatchError,VerificationError):fail('Current password incorrect',403)
        c.execute('UPDATE users SET password_hash=? WHERE id=?',(PH.hash(new),u['id']))
        c.execute('DELETE FROM sessions WHERE user_id=? AND token_hash<>?',(u['id'],digest(req.cookies.get('vyra_session',''))))
    audit_action(u,u['org_id'],'PASSWORD_CHANGED','Other sessions revoked')
    return {'ok':True}

@app.get('/api/dashboard')
async def dashboard(workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace)
    with connect() as c:
        stats=c.execute('''SELECT COUNT(*) orders,COALESCE(SUM(amount),0) volume,COALESCE(AVG(risk_score),0) avg_risk,
           SUM(CASE WHEN decision='DECLINE' THEN 1 ELSE 0 END) declined,
           SUM(CASE WHEN decision='REVIEW' THEN 1 ELSE 0 END) review_count FROM transactions WHERE org_id=?''',(org,)).fetchone()
        decisions=[dict(x) for x in c.execute('SELECT decision,COUNT(*) total FROM transactions WHERE org_id=? GROUP BY decision',(org,)).fetchall()]
        daily=[dict(x) for x in c.execute('''SELECT substr(ts,1,10) day,COUNT(*) count, SUM(CASE WHEN risk_score>=50 THEN 1 ELSE 0 END) high
                                    FROM transactions WHERE org_id=? GROUP BY day ORDER BY day DESC LIMIT 14''',(org,)).fetchall()][::-1]
        alerts=c.execute("SELECT COUNT(*) FROM alerts WHERE org_id=? AND status='OPEN'",(org,)).fetchone()[0]
        disputes=c.execute("SELECT COUNT(*) FROM disputes WHERE org_id=? AND status NOT IN ('WON','LOST','CLOSED','ACCEPTED')",(org,)).fetchone()[0]
        recent=[dict(x) for x in c.execute('''SELECT id,external_id,amount,product,ts,risk_score,decision,workflow
                               FROM transactions WHERE org_id=? ORDER BY id DESC LIMIT 7''',(org,)).fetchall()]
        suspicious_micro=c.execute('SELECT COUNT(*) FROM transactions WHERE org_id=? AND amount<=5 AND risk_score>=75',(org,)).fetchone()[0]
        testing=c.execute('SELECT COUNT(*) FROM card_events WHERE org_id=?',(org,)).fetchone()[0]
        organisation=c.execute('SELECT name,is_demo FROM orgs WHERE id=?',(org,)).fetchone()
    return {'workspace_name':organisation['name'],'is_demo':bool(organisation['is_demo']),
            'metrics':{**dict(stats),'alerts':alerts,'open_disputes':disputes,'micro_attempts':suspicious_micro+testing},
            'decisions':decisions,'daily':daily,'recent':recent,
            'scenario':{'aov':28000,'dispute_ratio':1.8,'attack_attempts':3000} if organisation['is_demo'] else None}

@app.get('/api/transactions')
async def transactions(workspace:str|None=None,q:str='',decision:str='ALL',page:int=1,u=Depends(require_user)):
    org=org_for(u,workspace);page=max(1,min(9999,page));decision=decision.upper();q=q[:60]
    where='WHERE org_id=?';params=[org]
    if decision in ('APPROVE','CHALLENGE','REVIEW','DECLINE'):
        where+=' AND decision=?';params.append(decision)
    if q:where+=' AND (external_id LIKE ? OR product LIKE ?)';params.extend(['%'+q+'%']*2)
    with connect() as c:
        count=c.execute('SELECT COUNT(*) FROM transactions '+where,params).fetchone()[0]
        rows=[dict(x) for x in c.execute('SELECT * FROM transactions '+where+' ORDER BY id DESC LIMIT 30 OFFSET ?',params+[(page-1)*30]).fetchall()]
    for row in rows:
        row['features']=json.loads(row['features']);row['reasons']=json.loads(row.pop('reason_json'))
    return {'items':rows,'total':count,'page':page,'pages':(count+29)//30 or 1}

@app.get('/api/transactions/{txid}')
async def transaction_detail(txid:int,workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace)
    with connect() as c:row=c.execute('SELECT * FROM transactions WHERE id=? AND org_id=?',(txid,org)).fetchone()
    if not row:fail('Transaction not found in your workspace',404)
    item=dict(row);item['features']=json.loads(item['features']);item['reasons']=json.loads(item.pop('reason_json'))
    return item

@app.post('/api/risk/evaluate')
async def risk_evaluate(req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);org=org_for(u,workspace)
    d=await body_json(req);order,_,_=enriched_order(org,d);return evaluate(order,org)

@app.post('/api/transactions')
async def transactions_create(req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);ensure_writable(u);org=org_for(u,workspace)
    return save_order(org,u,await body_json(req),'MANUAL')

@app.post('/api/transactions/import')
async def transactions_import(req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);ensure_writable(u);org=org_for(u,workspace)
    if int(req.headers.get('content-length','0'))>5*1024*1024:fail('CSV limit is 5 MB',413)
    raw=await req.body()
    if len(raw)>5*1024*1024:fail('CSV limit is 5 MB',413)
    try:
        data=raw.decode('utf-8-sig');reader=csv.DictReader(io.StringIO(data))
        if not reader.fieldnames or not {'transaction_id','amount'}.issubset(set(reader.fieldnames)):
            fail('CSV must include transaction_id and amount headers')
        unsafe={'pan','card_number','cvv','cvc','expiry','full_card_number','card_cvv','password','bank_account','account_number'}
        if set(f.lower().strip() for f in reader.fieldnames)&unsafe:
            fail('Remove payment credentials and sensitive columns before importing')
        inserted=0;skipped=0;errors=[]
        for i,row in enumerate(reader,2):
            if i>5001:fail('Import limit is 5,000 rows per file')
            if not any(str(v or '').strip() for v in row.values()):continue
            try:save_order(org,u,row,'CSV_IMPORT');inserted+=1
            except HTTPException as e:
                skipped+=1
                if len(errors)<12:errors.append({'row':i,'issue':str(e.detail)})
        audit_action(u,org,'CSV_IMPORTED',f'{inserted} inserted, {skipped} skipped')
        return {'inserted':inserted,'skipped':skipped,'errors':errors,'note':'Rows have been scored and stored in this private workspace.'}
    except UnicodeDecodeError:fail('CSV must be UTF-8')

@app.patch('/api/transactions/{txid}/review')
async def review_transaction(txid:int,req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);ensure_writable(u);org=org_for(u,workspace);d=await body_json(req)
    workflow=str(d.get('workflow','')).upper();notes=str(d.get('notes',''))[:1000]
    label=d.get('fraud_label')
    if workflow not in ('NEW','IN_REVIEW','CLEARED','ESCALATED','CLOSED'):fail('Invalid workflow')
    if label not in (None,0,1,'0','1'):fail('Invalid fraud label')
    with connect() as c:
        existing=c.execute('SELECT id FROM transactions WHERE id=? AND org_id=?',(txid,org)).fetchone()
        if not existing:fail('Transaction not found in your workspace',404)
        c.execute('UPDATE transactions SET workflow=?,notes=?,fraud_label=COALESCE(?,fraud_label) WHERE id=? AND org_id=?',
                  (workflow,notes,None if label is None else int(label),txid,org))
    audit_action(u,org,'TRANSACTION_REVIEW',f'{txid}: {workflow} / label {label}')
    return {'ok':True}

@app.get('/api/alerts')
async def alerts(workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace)
    with connect() as c:rows=[dict(r) for r in c.execute('SELECT * FROM alerts WHERE org_id=? ORDER BY id DESC LIMIT 150',(org,)).fetchall()]
    return {'items':rows}

@app.patch('/api/alerts/{alertid}')
async def resolve_alert(alertid:int,req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);ensure_writable(u);org=org_for(u,workspace)
    d=await body_json(req);state=str(d.get('status','')).upper()
    if state not in ('OPEN','ACKNOWLEDGED','RESOLVED'):fail('Invalid alert status')
    with connect() as c:
        cur=c.execute('UPDATE alerts SET status=? WHERE id=? AND org_id=?',(state,alertid,org))
        if not cur.rowcount:fail('Alert not found',404)
    audit_action(u,org,'ALERT_STATUS',f'{alertid}: {state}')
    return {'ok':True}

@app.get('/api/attack')
async def attack_monitor(workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace)
    with connect() as c:
        total=c.execute('SELECT COUNT(*) FROM card_events WHERE org_id=?',(org,)).fetchone()[0]
        unique=c.execute('SELECT COUNT(DISTINCT fingerprint) FROM card_events WHERE org_id=?',(org,)).fetchone()[0]
        bins=[dict(x) for x in c.execute('''SELECT substr(ts,12,2) hour,COUNT(*) total FROM card_events WHERE org_id=?
                                       GROUP BY hour ORDER BY hour''',(org,)).fetchall()]
        micro=c.execute('SELECT COUNT(*) FROM transactions WHERE org_id=? AND amount<=5',(org,)).fetchone()[0]
        high=c.execute('SELECT COUNT(*) FROM transactions WHERE org_id=? AND amount<=5 AND risk_score>=75',(org,)).fetchone()[0]
    return {'synthetic_attempts':total,'synthetic_fingerprints':unique,'synthetic_hourly':bins,
       'uploaded_micro_transactions':micro,'uploaded_high_risk_micro_transactions':high,
       'is_synthetic':bool(total),'note':'Demo attack events are isolated from real partner workspaces.'}

@app.get('/api/disputes')
async def disputes(workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace)
    with connect() as c:rows=[dict(r) for r in c.execute('SELECT * FROM disputes WHERE org_id=? ORDER BY due_date ASC',(org,)).fetchall()]
    for r in rows:r['evidence']=json.loads(r['evidence'])
    return {'items':rows}

@app.post('/api/disputes')
async def create_dispute(req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);ensure_writable(u);org=org_for(u,workspace);d=await body_json(req)
    case_ref=str(d.get('case_ref') or 'DSP-'+secrets.token_hex(4).upper())[:80]
    order_id=str(d.get('order_id') or '')[:80]
    reason=str(d.get('reason') or '')[:180]
    try:amount=float(d.get('amount',0))
    except (ValueError,TypeError):fail('Amount must be numeric')
    due=str(d.get('due_date') or expiry(72))[:40]
    if not order_id or not reason or amount<=0:fail('Order, reason, and positive amount are required')
    try:datetime.fromisoformat(due.replace('Z','+00:00'))
    except ValueError:fail('Invalid ISO due date')
    try:
        with connect() as c:
            c.execute('''INSERT INTO disputes(org_id,case_ref,order_id,amount,reason,due_date,status,evidence,created_at)
                 VALUES(?,?,?,?,?,?,?,?,?)''',(org,case_ref,order_id,amount,reason,due,'OPEN',json.dumps({}),now()))
    except sqlite3.IntegrityError:fail('Case reference already exists',409)
    audit_action(u,org,'DISPUTE_OPENED',case_ref)
    return {'ok':True,'case_ref':case_ref,'note':'Internal case only; no card-network submission occurred.'}

@app.patch('/api/disputes/{caseid}')
async def update_dispute(caseid:int,req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);ensure_writable(u);org=org_for(u,workspace);d=await body_json(req)
    status=str(d.get('status','OPEN')).upper()
    if status not in ('OPEN','GATHERING','READY','SUBMITTED','WON','LOST','ACCEPTED','CLOSED'):
        fail('Invalid dispute status')
    evidence=d.get('evidence',{})
    if not isinstance(evidence,dict) or len(json.dumps(evidence))>5000:fail('Evidence checklist is too large')
    # Descriptive evidence references only, not sensitive uploaded credentials.
    safe={str(k)[:64]:str(v)[:350] for k,v in evidence.items()}
    notes=str(d.get('notes',''))[:1000]
    with connect() as c:
        row=c.execute('SELECT evidence FROM disputes WHERE org_id=? AND id=?',(org,caseid)).fetchone()
        if not row:fail('Case not found',404)
        old=json.loads(row['evidence']);old.update(safe)
        c.execute('UPDATE disputes SET status=?,evidence=?,notes=? WHERE org_id=? AND id=?',
                  (status,json.dumps(old),notes,org,caseid))
    audit_action(u,org,'DISPUTE_UPDATED',f'{caseid}: {status}')
    return {'ok':True,'note':'Saved to internal case management; not sent to an issuer or network.'}

@app.get('/api/disputes/{caseid}/evidence')
async def evidence(caseid:int,workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace)
    with connect() as c:row=c.execute('SELECT * FROM disputes WHERE org_id=? AND id=?',(org,caseid)).fetchone()
    if not row:fail('Case not found',404)
    audit_action(u,org,'EVIDENCE_EXPORTED',str(caseid))
    item=dict(row);item['evidence']=json.loads(item['evidence'])
    return {'type':'INTERNAL_DISPUTE_PACKET','data':item,
            'checklist':['Transaction receipt','Issuer authentication result (when lawful)','Customer consent / order trail',
                         'Delivery confirmation','Refund history','Customer correspondence'],
            'warning':'Not automatically submitted to a bank/card network. Verify actual deadlines and network reason-code rules.'}

@app.get('/api/model')
async def model_info(workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace);m=tenant_model(org)
    with connect() as c:
        labels=c.execute('''SELECT COUNT(*) n,COALESCE(SUM(CASE WHEN fraud_label=1 THEN 1 ELSE 0 END),0) fraud,
                         COALESCE(SUM(CASE WHEN fraud_label=0 THEN 1 ELSE 0 END),0) legit
                         FROM transactions WHERE org_id=? AND fraud_label IS NOT NULL''',(org,)).fetchone()
    return {'model':{'version':m['version'],'source':m['source'],'metrics':m['metrics'],'trained':m['trained']},
            'labels':dict(labels),'features':FEATURES,'bands':{'APPROVE':'0-24','CHALLENGE':'25-49','REVIEW':'50-74','DECLINE':'75-100'},
            'warning':'Synthetic model metrics are simulation-only; partner model metrics use held-out labelled merchant records and need validation.'}

@app.post('/api/model/train')
async def train_model(req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner','partner_admin');org=org_for(u,workspace)
    with connect() as c:
        rows=[dict(r) for r in c.execute('''SELECT features,fraud_label FROM transactions WHERE org_id=? AND fraud_label IS NOT NULL
                                     ORDER BY ts ASC,id ASC''',(org,)).fetchall()]
    prepared=[{**json.loads(r['features']),'fraud_label':r['fraud_label']} for r in rows]
    try:result=train_tenant(org,prepared)
    except ValueError as e:fail(str(e))
    audit_action(u,org,'MODEL_TRAINED',result['version'])
    return {'ok':True,'model':result,'disclaimer':'This model requires additional calibration, monitoring, and validation before production use.'}

@app.get('/api/audit')
async def audit_trail(workspace:str|None=None,u=Depends(require_user)):
    org=org_for(u,workspace)
    with connect() as c:rows=[dict(x) for x in c.execute('''SELECT a.id,a.created_at,a.action,a.detail,u.display_name actor
                           FROM audit a LEFT JOIN users u ON u.id=a.actor_id WHERE a.org_id=? ORDER BY a.id DESC LIMIT 100''',(org,)).fetchall()]
    return {'items':rows}

@app.get('/api/integrations/keys')
async def list_keys(workspace:str|None=None,u=Depends(require_user)):
    require_role(u,'owner','partner_admin');org=org_for(u,workspace)
    with connect() as c:rows=[dict(x) for x in c.execute('SELECT id,name,created_at,revoked FROM api_keys WHERE org_id=? ORDER BY id DESC',(org,)).fetchall()]
    return {'items':rows}

@app.post('/api/integrations/keys')
async def key_create(req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner','partner_admin');org=org_for(u,workspace)
    d=await body_json(req);name=str(d.get('name') or 'Merchant connector')[:70]
    key='vyra_'+secrets.token_urlsafe(36)
    with connect() as c:c.execute('INSERT INTO api_keys(org_id,owner_id,name,key_hash,created_at) VALUES(?,?,?,?,?)',
       (org,u['id'],name,digest(key),now()))
    audit_action(u,org,'API_KEY_CREATED',name)
    return {'key':key,'note':'Shown once. Store privately. Use HTTPS for integrations. Send X-API-Key header.'}

@app.patch('/api/integrations/keys/{keyid}')
async def key_revoke(keyid:int,req:Request,workspace:str|None=None,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner','partner_admin');org=org_for(u,workspace)
    with connect() as c:
        n=c.execute('UPDATE api_keys SET revoked=1 WHERE org_id=? AND id=?',(org,keyid)).rowcount
        if not n:fail('Key not found',404)
    audit_action(u,org,'API_KEY_REVOKED',str(keyid));return {'ok':True}

@app.post('/api/ingest')
async def ingest_event(req:Request):
    key=req.headers.get('x-api-key','')
    if not key or len(key)>256:fail('Valid API key required',401)
    with connect() as c:
        row=c.execute('''SELECT a.org_id,a.owner_id,o.status,o.is_demo FROM api_keys a JOIN orgs o ON o.id=a.org_id
                         WHERE a.key_hash=? AND a.revoked=0''',(digest(key),)).fetchone()
    if not row or row['status']!='ACTIVE' or row['is_demo']:fail('API key unavailable',401)
    d=await body_json(req)
    return save_order(row['org_id'],{'id':row['owner_id']},d,'API_INGEST')

@app.get('/api/admin/orgs')
async def admin_orgs(u=Depends(require_user)):
    require_role(u,'owner')
    with connect() as c:
        rows=[dict(r) for r in c.execute('''SELECT o.id,o.name,o.status,o.is_demo,o.created_at,
          (SELECT COUNT(*) FROM users WHERE org_id=o.id AND role!='demo') user_count,
          (SELECT COUNT(*) FROM transactions WHERE org_id=o.id) transaction_count
          FROM orgs o WHERE o.is_demo=0 ORDER BY id''').fetchall()]
    return {'items':rows}

@app.post('/api/admin/orgs')
async def create_org(req:Request,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner');d=await body_json(req)
    name=str(d.get('name','')).strip()[:100]
    if len(name)<3:fail('Workspace name must have 3+ characters')
    try:
        with connect() as c:
            cur=c.execute('INSERT INTO orgs(name,status,is_demo,created_at) VALUES(?,?,0,?)',(name,'ACTIVE',now()))
            id_=cur.lastrowid
    except sqlite3.IntegrityError:fail('Workspace name already exists',409)
    audit_action(u,u['org_id'],'ORG_CREATED',f'{id_}: {name}');return {'ok':True,'org_id':id_}

@app.patch('/api/admin/orgs/{orgid}')
async def org_status(orgid:int,req:Request,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner');d=await body_json(req)
    status=str(d.get('status','')).upper()
    if status not in ('ACTIVE','SUSPENDED'):fail('Invalid workspace status')
    if orgid==u['org_id']:fail('Cannot suspend the headquarters workspace')
    with connect() as c:
        n=c.execute('UPDATE orgs SET status=? WHERE id=? AND is_demo=0',(status,orgid)).rowcount
        if not n:fail('Workspace not found',404)
        if status=='SUSPENDED':
            c.execute('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE org_id=?)',(orgid,))
    audit_action(u,u['org_id'],'ORG_STATUS',f'{orgid}: {status}')
    return {'ok':True}

@app.get('/api/admin/users')
async def admin_users(u=Depends(require_user)):
    require_role(u,'owner')
    with connect() as c:
        rows=[dict(r) for r in c.execute('''SELECT u.id,u.display_name,u.email,u.role,u.active,u.created_at,u.last_login,o.name org_name,o.id org_id,
                          (SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.id AND s.expires>?) AS active_sessions
                         FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.role!='demo' ORDER BY u.id''',(epoch(),)).fetchall()]
    return {'items':rows}

@app.post('/api/admin/invite')
async def admin_invite(req:Request,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner');d=await body_json(req)
    email=str(d.get('email','')).strip().lower();org=int(d.get('org_id') or 0);role=str(d.get('role','analyst'))
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email):fail('Invalid email address')
    if role not in ('partner_admin','analyst','viewer'):fail('Invalid role')
    with connect() as c:
        space=c.execute('SELECT id FROM orgs WHERE id=? AND is_demo=0 AND status=?',(org,'ACTIVE')).fetchone()
        if not space:fail('Active partner workspace required')
        if c.execute('SELECT 1 FROM users WHERE email=?',(email,)).fetchone():fail('Email is already registered',409)
        token=secrets.token_urlsafe(32)
        c.execute('INSERT INTO invites(token_hash,email,role,org_id,created_by,expires,created_at) VALUES(?,?,?,?,?,?,?)',
                  (digest(token),email,role,org,u['id'],epoch()+48*3600,now()))
    audit_action(u,org,'INVITED_PARTNER',f'{email} ({role})')
    return {'ok':True,'invite_path':'/?invite='+token,'expires_hours':48,'recipient':email,
            'note':'Copy the private invite link. This app does not automatically email invites.'}

@app.patch('/api/admin/users/{userid}')
async def toggle_user(userid:int,req:Request,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner');d=await body_json(req)
    active=d.get('active')
    if not isinstance(active,bool):fail('active must be true or false')
    with connect() as c:
        target=c.execute('SELECT role,org_id,email FROM users WHERE id=?',(userid,)).fetchone()
        if not target or target['role'] in ('owner','demo'):fail('This account cannot be changed',403)
        c.execute('UPDATE users SET active=? WHERE id=?',(int(active),userid))
        if not active:c.execute('DELETE FROM sessions WHERE user_id=?',(userid,))
    audit_action(u,target['org_id'],'USER_STATUS',f"{target['email']}: {'ACTIVE' if active else 'SUSPENDED'}")
    return {'ok':True}

@app.post('/api/admin/users/{userid}/revoke-sessions')
async def revoke_sessions(userid:int,req:Request,u=Depends(require_user)):
    check_csrf(req,u);require_role(u,'owner')
    with connect() as c:
        row=c.execute('SELECT role,email,org_id FROM users WHERE id=?',(userid,)).fetchone()
        if not row or row['role'] in ('owner','demo'):fail('Partner account required',403)
        c.execute('DELETE FROM sessions WHERE user_id=?',(userid,))
    audit_action(u,row['org_id'],'USER_SESSIONS_REVOKED',row['email'])
    return {'ok':True,'message':'Partner sessions revoked. Partner may sign in again if active.'}

@app.get('/api/about')
def about():return {'product':'DM – GADGET HUB','platform':'VYRA Risk OS','creator':'Divy Mathur',
    'contact':'divymathur12345678901@gmail.com','purpose':'Fraud review, payments risk analysis and internal chargeback operations',
    'version':'2.0 / multi-tenant prototype','model_notice':'Synthetic baseline unless a merchant-specific model was trained.'}

@app.get('/api/template')
async def csv_template(u=Depends(require_user)):
    headers=['transaction_id','timestamp','amount','product','device_ref','account_ref','payment_status','new_address','new_device','recent_address_change','failed_logins',
        'attempt_velocity','account_new','odd_hour','proxy_signal','declines_1h','shipping_billing_mismatch','fraud_label']
    buf=io.StringIO();writer=csv.writer(buf);writer.writerow(headers)
    return Response(buf.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="vyra_import_template.csv"'})

if __name__=='__main__':
    import uvicorn
    host=os.getenv('HOST','127.0.0.1');port=int(os.getenv('PORT','8765'))
    if not has_owner():
        print('No owner account found. Run python setup_owner.py first.');sys.exit(1)
    uvicorn.run(app,host=host,port=port,log_level='info')
