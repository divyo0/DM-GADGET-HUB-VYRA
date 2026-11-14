"""Local integration suite. Uses a temporary database and synthetic test records only."""
import sys, tempfile, pathlib, json, io
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import pytest, storage, app
from fastapi.testclient import TestClient

@pytest.fixture()
def environment(monkeypatch):
    with tempfile.TemporaryDirectory(prefix='vyra_tests_') as d:
        monkeypatch.setattr(storage,'DB',pathlib.Path(d)/'test.sqlite3')
        app.ATTEMPTS.clear()
        storage.init()
        storage.create_owner('SecureOwnerPassword#2026')
        # Authentication bypass is intentionally limited to temporary demo tenant.
        with TestClient(app.app) as client:
            yield client

def sign_owner(c):
    r=c.post('/api/auth/login',json={'email':storage.OWNER_EMAIL,'password':'SecureOwnerPassword#2026'})
    assert r.status_code==200,r.text
    assert r.json()['otp_required'] is False
    me=c.get('/api/me').json()
    assert me['role']=='owner'
    return me

def test_health_and_owner_setup(environment):
    c=environment
    assert c.get('/api/health').json()['ok']
    assert c.get('/api/bootstrap').json()['owner_initialized']
    assert c.get('/api/me').status_code==401
    owner=sign_owner(c)
    assert owner['name']=='Divy Mathur'

def test_risk_real_scoring_and_persistence(environment):
    c=environment;u=sign_owner(c);h={'X-CSRF-Token':u['csrf']}
    clean=c.post('/api/risk/evaluate',json={'amount':28000},headers=h)
    attack=c.post('/api/risk/evaluate',json={'amount':1,'attempt_velocity':30,'declines_1h':20},headers=h)
    ato=c.post('/api/risk/evaluate',json={'amount':60000,'new_device':True,'failed_logins':5,'recent_address_change':True},headers=h)
    assert clean.status_code==attack.status_code==ato.status_code==200
    assert attack.json()['risk_score']>=95
    assert ato.json()['risk_score']>=85
    assert attack.json()['decision']=='DECLINE'
    add=c.post('/api/transactions',json={'transaction_id':'ACTUAL-001','amount':48000,'new_device':True},headers=h)
    assert add.status_code==200,add.text
    detail=c.get('/api/transactions/'+str(add.json()['id']))
    assert detail.json()['external_id']=='ACTUAL-001'
    assert detail.json()['source']=='MANUAL'
    assert c.post('/api/transactions',json={'transaction_id':'ACTUAL-001','amount':48000},headers=h).status_code==409

def test_csrf_is_required(environment):
    c=environment;sign_owner(c)
    assert c.post('/api/risk/evaluate',json={'amount':1}).status_code==403

def test_csv_import_and_dispute_lifecycle(environment):
    c=environment;u=sign_owner(c);h={'X-CSRF-Token':u['csrf']}
    csvbytes='transaction_id,amount,product,attempt_velocity\nMERCH-1,28000,Laptop,1\nMERCH-2,1,Phone,35\n'.encode()
    r=c.post('/api/transactions/import',content=csvbytes,headers={**h,'Content-Type':'text/csv'})
    assert r.status_code==200,r.text
    assert r.json()['inserted']==2
    assert c.get('/api/dashboard').json()['metrics']['orders']==2
    disp=c.post('/api/disputes',json={'order_id':'MERCH-1','amount':28000,'reason':'Unauthorized transaction'},headers=h)
    assert disp.status_code==200
    row=c.get('/api/disputes').json()['items'][0]
    upd=c.patch('/api/disputes/'+str(row['id']),json={'status':'GATHERING','evidence':{'receipt':'INV-111'},'notes':'Evidence needed'},headers=h)
    assert upd.status_code==200
    pkt=c.get('/api/disputes/'+str(row['id'])+'/evidence')
    assert pkt.json()['data']['evidence']['receipt']=='INV-111'

def test_partner_isolation_and_owner_control(environment):
    owner=environment;u=sign_owner(owner);h={'X-CSRF-Token':u['csrf']}
    org=owner.post('/api/admin/orgs',json={'name':'Test Merchant Pvt Ltd'},headers=h)
    assert org.status_code==200
    orgid=org.json()['org_id']
    invite=owner.post('/api/admin/invite',json={'email':'analyst@example.com','role':'analyst','org_id':orgid},headers=h)
    assert invite.status_code==200
    path=invite.json()['invite_path']
    token=path.split('invite=')[1]
    assert owner.post('/api/auth/activate',json={'token':token,'name':'Partner Analyst','password':'PartnerPassword#2026'}).status_code==200
    with TestClient(app.app) as partner:
        r=partner.post('/api/auth/login',json={'email':'analyst@example.com','password':'PartnerPassword#2026'})
        assert r.status_code==200,r.text
        p=partner.get('/api/me').json();hp={'X-CSRF-Token':p['csrf']}
        assert p['role']=='analyst'
        assert partner.get('/api/dashboard').json()['metrics']['orders']==0
        assert partner.get('/api/dashboard?workspace='+str(u['org_id'])).json()['metrics']['orders']==0
        assert partner.get('/api/admin/users').status_code==403
        assert partner.post('/api/transactions',json={'transaction_id':'PARTNER-001','amount':39000},headers=hp).status_code==200
        assert owner.get('/api/dashboard').json()['metrics']['orders']==0
        assert owner.get('/api/dashboard?workspace='+str(orgid)).json()['metrics']['orders']==1
        # Suspend account and invalidate sessions immediately.
        users=owner.get('/api/admin/users').json()['items']
        pid=next(x['id'] for x in users if x['email']=='analyst@example.com')
        assert owner.patch('/api/admin/users/'+str(pid),json={'active':False},headers=h).status_code==200
        assert partner.get('/api/me').status_code==401

def test_review_synthetic_data_only_in_demo(environment):
    with TestClient(app.app) as client:
        r=client.post('/api/auth/demo')
        assert r.status_code==200,r.text
        me=client.get('/api/me').json()
        assert me['role']=='demo'
        assert client.get('/api/dashboard').json()['is_demo']
        assert client.get('/api/attack').json()['synthetic_attempts']==3000
        assert client.get('/api/admin/users').status_code==403
        assert client.get('/api/integrations/keys').status_code==403

def test_key_ingestion_and_revoke(environment):
    c=environment;u=sign_owner(c);h={'X-CSRF-Token':u['csrf']}
    key=c.post('/api/integrations/keys',json={'name':'POS Backoffice'},headers=h)
    assert key.status_code==200
    secret=key.json()['key']
    good=c.post('/api/ingest',json={'transaction_id':'API-1','amount':38000},headers={'X-API-Key':secret})
    assert good.status_code==200,good.text
    keyid=c.get('/api/integrations/keys').json()['items'][0]['id']
    assert c.patch('/api/integrations/keys/'+str(keyid),json={},headers=h).status_code==200
    assert c.post('/api/ingest',json={'transaction_id':'API-2','amount':30000},headers={'X-API-Key':secret}).status_code==401

def test_model_is_executable(environment):
    c=environment;u=sign_owner(c);h={'X-CSRF-Token':u['csrf']}
    m=c.get('/api/model').json()
    assert m['model']['source']=='synthetic'
    assert m['model']['metrics']['test_samples']>0
    assert c.post('/api/model/train',json={},headers=h).status_code==400

def test_reject_card_secret_columns(environment):
    c=environment;u=sign_owner(c);h={'X-CSRF-Token':u['csrf'],'Content-Type':'text/csv'}
    r=c.post('/api/transactions/import',content=b'transaction_id,amount,cvv\n1,28,123\n',headers=h)
    assert r.status_code==400
    assert 'sensitive' in r.text


def test_real_velocity_derived_from_opaque_device_ref(environment):
    c=environment;u=sign_owner(c);h={'X-CSRF-Token':u['csrf']}
    last=None
    for i in range(12):
        r=c.post('/api/transactions',headers=h,json={'transaction_id':f'VEL-{i}', 'amount':1,
                   'device_ref':'hashed-device-A','payment_status':'DECLINED'})
        assert r.status_code==200,r.text
        last=r.json()
    assert last['risk_score']>=95,last
    assert last['decision']=='DECLINE'
    record=c.get('/api/transactions/'+str(last['id'])).json()
    assert record['features']['attempt_velocity']>=10
    assert record['features']['declines_1h']>=9
    assert record['device_hash']!= 'hashed-device-A'
    assert len(record['device_hash'])==64

def test_admin_session_termination(environment):
    owner=environment;u=sign_owner(owner);h={'X-CSRF-Token':u['csrf']}
    oid=owner.post('/api/admin/orgs',json={'name':'Session Demo Org'},headers=h).json()['org_id']
    path=owner.post('/api/admin/invite',json={'email':'staff@test.co','role':'viewer','org_id':oid},headers=h).json()['invite_path']
    token=path.split('invite=')[1]
    owner.post('/api/auth/activate',json={'token':token,'name':'Staff Viewer','password':'SecureViewerPassword#2026'})
    with TestClient(app.app) as partner:
        assert partner.post('/api/auth/login',json={'email':'staff@test.co','password':'SecureViewerPassword#2026'}).status_code==200
        sid=next(i['id'] for i in owner.get('/api/admin/users').json()['items'] if i['email']=='staff@test.co')
        assert owner.post(f'/api/admin/users/{sid}/revoke-sessions',headers=h,json={}).status_code==200
        assert partner.get('/api/me').status_code==401


def test_api_rejects_secret_card_fields(environment):
    c=environment;u=sign_owner(c);h={'X-CSRF-Token':u['csrf']}
    r=c.post('/api/transactions',headers=h,json={'amount':1000,'card_number':'4111111111111111','cvv':'123'})
    assert r.status_code==400
    assert 'sensitive' in r.text
