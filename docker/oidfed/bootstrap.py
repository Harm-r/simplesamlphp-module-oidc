#!/usr/bin/env python3
"""Bootstrap the local trust anchor and enroll the lab's leaf entities."""
import base64
import json
from pathlib import Path
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LAB = Path(__file__).resolve().parent
STATE = LAB.parents[1] / 'build' / 'oidfed-lab'
CA = ssl.create_default_context(cafile=str(STATE / 'pki' / 'ca.crt'))
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=CA))
ADMIN = 'http://127.0.0.1:9763/api/v1/admin'
TA = 'https://ta.127.0.0.1.nip.io:9443'
AUTH = 'Basic ' + base64.b64encode(b'lab-admin:oidfed-lab-admin').decode()


def request(url, data=None, method=None, admin=False):
    headers = {'Content-Type': 'application/json'}
    if admin:
        headers['Authorization'] = AUTH
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with OPENER.open(req, timeout=10) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'{url}: HTTP {error.code}: {error.read().decode()[:600]}') from error


def wait(url, admin=False):
    deadline = time.monotonic() + 90
    while True:
        try:
            return request(url, admin=admin)
        except (OSError, RuntimeError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(f'Not ready: {url}: {error}') from error
            time.sleep(1)


def configuration(entity):
    token = wait(entity + '/.well-known/openid-federation').decode()
    payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
    if payload['iss'] != entity or payload['sub'] != entity:
        raise RuntimeError('Entity Configuration has unexpected issuer/subject')
    return token, payload


if len(sys.argv) != 2 or sys.argv[1] not in ('anchor', 'enroll'):
    raise SystemExit('Usage: bootstrap.py anchor|enroll')

if sys.argv[1] == 'anchor':
    users = json.loads(wait(ADMIN + '/users', admin=True)) or []
    if not any(user['username'] == 'lab-admin' for user in users):
        request(ADMIN + '/users', {'username': 'lab-admin', 'password': 'oidfed-lab-admin'}, admin=True)
    token, payload = configuration(TA)
    # Initial trust is established from the locally deployed TA over our lab CA.
    # Downstream protocol validation verifies statements using this pinned set.
    shared = STATE / 'shared'
    temporary = shared / 'ta-jwks.tmp'
    temporary.write_text(json.dumps(payload['jwks'], indent=2))
    temporary.replace(shared / 'ta-jwks.json')
    (shared / 'ta-configuration.jwt').write_text(token)
    print('Pinned Lighthouse public keys:', [key['kid'] for key in payload['jwks']['keys']])
else:
    known = json.loads(request(ADMIN + '/subordinates', admin=True)) or []
    for role, entity_type in [('op', 'openid_provider'), ('rp', 'openid_relying_party')]:
        entity = f'https://{role}.127.0.0.1.nip.io:9443'
        token, payload = configuration(entity)
        data = {'entity_id': entity, 'status': 0, 'description': 'Local ML-DSA interoperability lab',
                'registered_entity_types': [entity_type], 'jwks': payload['jwks']}
        existing = next((item for item in known if item['entity_id'] == entity), None)
        if existing is not None:
            path = ADMIN + '/subordinates/' + str(existing['id'])
            request(path, data, method='PUT', admin=True)
            request(path + '/jwks', payload['jwks'], method='PUT', admin=True)
        else:
            request(ADMIN + '/subordinates', data, admin=True)
        (STATE / 'shared' / (role + '-configuration.jwt')).write_text(token)
        print('Enrolled', entity, 'with', len(payload['jwks']['keys']), 'Federation keys')
