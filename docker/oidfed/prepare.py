#!/usr/bin/env python3
"""Create local TLS material and render the lab configuration without replacing keys."""
import os
from pathlib import Path
import subprocess

LAB = Path(__file__).resolve().parent
STATE = LAB.parents[1] / 'build' / 'oidfed-lab'
algorithm = os.environ.get('OIDFED_ALG', 'ML-DSA-44')
if algorithm not in ('RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
    raise SystemExit('OIDFED_ALG must be RS256, ML-DSA-44, ML-DSA-65 or ML-DSA-87')
pki = STATE / 'pki'
pki.mkdir(parents=True, exist_ok=True)
(STATE / 'shared').mkdir(exist_ok=True)

def openssl(*arguments):
    subprocess.run(['openssl', *map(str, arguments)], check=True, capture_output=True)

if not (pki / 'ca.key').exists():
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365',
            '-keyout', pki / 'ca.key', '-out', pki / 'ca.crt', '-subj', '/CN=OIDFed ML-DSA Lab CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
if not (pki / 'server.key').exists():
    openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', pki / 'server.key',
            '-out', pki / 'server.csr', '-subj', '/CN=app.127.0.0.1.nip.io')
if not (pki / 'server.crt').exists():
    extensions = pki / 'server.ext'
    extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join(
                              'DNS:' + role + '.127.0.0.1.nip.io' for role in ('app', 'op', 'rp', 'ta')) + '\n')
    openssl('x509', '-req', '-in', pki / 'server.csr', '-CA', pki / 'ca.crt', '-CAkey', pki / 'ca.key',
            '-CAcreateserial', '-out', pki / 'server.crt', '-days', '90', '-sha256', '-extfile', extensions)
for key in pki.glob('*.key'):
    key.chmod(0o600)
for component in ('lighthouse', 'offa'):
    template = (LAB / (component + '.yml.template')).read_text()
    (STATE / (component + '.yml')).write_text(template.replace('@ALG@', algorithm))
(LAB / '.env').write_text('OIDFED_ALG=' + algorithm + '\n')
print('Prepared', algorithm, 'lab; CA:', pki / 'ca.crt')
