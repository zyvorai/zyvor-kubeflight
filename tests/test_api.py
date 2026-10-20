# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
from fastapi.testclient import TestClient
from kubeflight.server import app

c=TestClient(app)
def test_health():
    r=c.get('/api/healthz'); assert r.status_code==200 and r.json()['status']=='ok'
def test_home():
    r=c.get('/'); assert r.status_code==200 and 'Know what will break' in r.text
def test_check():
    y='apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n'
    r=c.post('/api/check',json={'manifests':y}); assert r.status_code==200 and r.json()['resources']==1
def test_bad_yaml():
    r=c.post('/api/check',json={'manifests':'a: ['}); assert r.status_code==400

def test_probes_exempt_from_rate_limit(monkeypatch):
    from kubeflight import server
    server.HITS.clear(); monkeypatch.setattr(server,'RATE',2)
    try:
        assert [c.get('/api/healthz').status_code for _ in range(5)]==[200]*5
        assert [c.get('/api/demo').status_code for _ in range(3)]==[200,200,429]
    finally: server.HITS.clear()

def test_idle_hits_evicted(monkeypatch):
    from kubeflight import server
    server.HITS.clear()
    for i in range(1100): server.HITS[f'10.0.{i}.1'].append(0.0)
    try:
        assert c.get('/api/demo').status_code==200
        assert len(server.HITS)<=2
    finally: server.HITS.clear()
