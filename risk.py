"""VYRA Risk OS: supervised baseline + transparent policy overrides.
Model is trained on SYNTHETIC training examples until a tenant explicitly trains
from its own reviewed/labelled transactions. No bank or network integrations.
"""
from __future__ import annotations
import json, math, os, random, threading, time
from pathlib import Path
import numpy as np
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import precision_score, recall_score, confusion_matrix, roc_auc_score

ROOT = Path(__file__).resolve().parent
MODELS = ROOT / 'private_data' / 'models'
MODELS.mkdir(exist_ok=True)
BASELINE_PATH = MODELS / 'baseline_synthetic_v2.joblib'
FEATURES = ['amount','new_address','new_device','recent_address_change','failed_logins',
            'attempt_velocity','account_new','odd_hour','proxy_signal','declines_1h','shipping_billing_mismatch']
_LOCK = threading.Lock()
_CACHE={}


def normalized(data):
    try:
        d={'amount': max(0,min(5000000,float(data.get('amount') or 0))),
          'failed_logins': max(0,min(1000,int(float(data.get('failed_logins') or 0)))),
          'attempt_velocity': max(0,min(100000,int(float(data.get('attempt_velocity') or 1)))),
          'declines_1h': max(0,min(100000,int(float(data.get('declines_1h') or 0))))}
    except (ValueError,TypeError): raise ValueError('Amount and count fields must be numeric')
    for f in FEATURES:
        if f not in d:
            v=data.get(f,False)
            d[f]=v is True or str(v).strip().lower() in ('1','true','yes','y','on')
    if not math.isfinite(d['amount']):raise ValueError('Invalid transaction amount')
    return d


def vector(d):
    return [float(d[f]) for f in FEATURES]


def _make_synthetic(n=4800, seed=411):
    rng=random.Random(seed)
    x=[]; y=[]
    for _ in range(n):
        amount=min(200000,max(1,rng.lognormvariate(10.2,.72)))
        d={ 'amount':amount,'new_address':rng.random()<.31,'new_device':rng.random()<.28,
            'recent_address_change':rng.random()<.09,'failed_logins':rng.choices([0,1,2,4,8],[.67,.14,.10,.07,.02])[0],
            'attempt_velocity':rng.choices([1,2,3,7,14,28],[.55,.22,.12,.06,.04,.01])[0],
            'account_new':rng.random()<.20,'odd_hour':rng.random()<.25,'proxy_signal':rng.random()<.09,
            'declines_1h':rng.choices([0,1,3,8,18],[.66,.17,.10,.05,.02])[0],
            'shipping_billing_mismatch':rng.random()<.15}
        z=(-4.1 +.000013*amount + .48*d['new_address']+.75*d['new_device']+
           1.3*d['recent_address_change']+.28*d['failed_logins']+.10*d['attempt_velocity']+
           .28*d['account_new']+.15*d['odd_hour']+.9*d['proxy_signal']+.11*d['declines_1h']+
           .72*d['shipping_billing_mismatch']+
           1.5*(d['new_device'] and d['recent_address_change'])+
           2.0*(amount<=5 and d['attempt_velocity']>=10))
        p=1/(1+math.exp(-max(-20,min(20,z))))
        x.append(vector(d));y.append(int(rng.random()<p))
    return np.array(x,dtype=float),np.array(y,dtype=int)


def _metrics(m,xt,yt):
    p=m.predict_proba(xt)[:,1];pred=(p>=.50).astype(int)
    return {'precision': round(float(precision_score(yt,pred,zero_division=0)),3),
            'recall':round(float(recall_score(yt,pred,zero_division=0)),3),
            'false_positive_rate':round(float(((pred==1)&(yt==0)).sum()/max(1,(yt==0).sum())),3),
            'auc':round(float(roc_auc_score(yt,p)),3) if len(set(yt))==2 else None,
            'test_samples':len(yt)}


def baseline():
    with _LOCK:
        if 'baseline' not in _CACHE:
            if BASELINE_PATH.exists():
                _CACHE['baseline']=joblib.load(BASELINE_PATH)
            else:
                x,y=_make_synthetic()
                split=int(.8*len(y))
                m=HistGradientBoostingClassifier(max_iter=130,max_leaf_nodes=15,learning_rate=.07,l2_regularization=1,random_state=42)
                m.fit(x[:split],y[:split]); result={'model':m,'metrics':_metrics(m,x[split:],y[split:]),'source':'synthetic',
                    'version':'HGB-2026 / synthetic baseline','trained':int(time.time())}
                joblib.dump(result,BASELINE_PATH)
                _CACHE['baseline']=result
        return _CACHE['baseline']


def tenant_model(org_id):
    path=MODELS / f'partner_{int(org_id)}.joblib'
    if not path.exists(): return baseline()
    with _LOCK:
        key=str(path)
        if key not in _CACHE:_CACHE[key]=joblib.load(path)
        return _CACHE[key]


def train_tenant(org_id, rows):
    """Only reviewed, labelled orders. Row order must be time-ordered by caller."""
    data=[];y=[]
    for row in rows:
        if row.get('fraud_label') in (0,1,'0','1'):
            d=normalized(row)
            data.append(vector(d));y.append(int(row['fraud_label']))
    if len(y)<100 or sum(y)<15 or len(y)-sum(y)<35:
        raise ValueError('Need at least 100 labelled orders, including 15 fraud and 35 legitimate records')
    cut=int(len(y)*.8)
    if len(set(y[:cut]))<2 or len(set(y[cut:]))<2:
        raise ValueError('Both classes must be present in training and time-based test sets')
    x=np.array(data,float);yv=np.array(y,int)
    m=HistGradientBoostingClassifier(max_iter=140,max_leaf_nodes=15,learning_rate=.06,l2_regularization=2,random_state=42)
    m.fit(x[:cut],yv[:cut]);res={'model':m,'metrics':_metrics(m,x[cut:],yv[cut:]),
       'source':'merchant labels','version':f'ORG-{org_id}-{int(time.time())}','trained':int(time.time()),'train_samples':cut}
    path=MODELS / f'partner_{int(org_id)}.joblib';joblib.dump(res,path)
    with _LOCK:_CACHE[str(path)]=res
    return {k:v for k,v in res.items() if k!='model'}


def evaluate(data,org_id=None):
    d=normalized(data);reasons=[];pts=0
    rules=[('new_address',10,'Unfamiliar shipping destination'),('new_device',10,'First-seen device'),
        ('recent_address_change',20,'Recent shipping address change'),('account_new',7,'Limited account history'),
        ('odd_hour',5,'Unusual checkout hour'),('proxy_signal',14,'Unusual network signal'),
        ('shipping_billing_mismatch',10,'Shipping / billing mismatch')]
    for f,w,r in rules:
        if d[f]:pts+=w;reasons.append({'factor':r,'weight':w})
    if d['amount']>60000:pts+=12;reasons.append({'factor':'High value electronics purchase','weight':12})
    if d['failed_logins']>=3:pts+=20;reasons.append({'factor':'Multiple failed account sign-ins','weight':20})
    if d['attempt_velocity']>=10:pts+=34;reasons.append({'factor':'Unusually high payment attempt velocity','weight':34})
    elif d['attempt_velocity']>=5:pts+=15;reasons.append({'factor':'Elevated payment attempt velocity','weight':15})
    if d['declines_1h']>=5:pts+=16;reasons.append({'factor':'Recent repeated declines','weight':16})
    result=tenant_model(org_id) if org_id else baseline()
    proba=float(result['model'].predict_proba(np.array([vector(d)],float))[0,1]);
    score=int(round(.72*min(100,pts)+.28*(proba*100)))
    guardrails=[]
    if d['amount']<=5 and d['attempt_velocity']>=10:
        score=max(96,score);guardrails.append('Micro-payment enumeration safeguard')
    if d['new_device'] and d['recent_address_change'] and d['failed_logins']>=3:
        score=max(88,score);guardrails.append('Account takeover safeguard')
    if d['attempt_velocity']>=25 and d['declines_1h']>=10:
        score=max(95,score);guardrails.append('Mass-decline / card-testing safeguard')
    decision='APPROVE' if score<25 else 'CHALLENGE' if score<50 else 'REVIEW' if score<75 else 'DECLINE'
    return {'risk_score':min(100,score),'decision':decision,'risk_probability':round(proba,4),
            'rule_points':min(100,pts),'reasons':reasons or [{'factor':'No elevated risk signals','weight':0}],
            'guardrails':guardrails,'model_version':result['version'],'model_source':result['source'],
            'model_metrics':result['metrics'],
            'disclaimer':'Risk recommendations only. Not a gateway decline, issuer authorization, or verified real-world AI accuracy.'}
