# ML-DSA Federation interoperability lab

This is a separate lab alongside `docker/mldsa`. Lighthouse is the trust anchor;
SSP is the OpenID Provider; OFFA is the Relying Party and forward-auth service
protecting a tiny application. Both leaf entities are enrolled with Lighthouse.
Client registration at SSP happens automatically through Federation on login.

The lab uses the current module checkout and its installed Composer dependencies,
including a sibling OpenID checkout when `vendor/simplesamlphp/openid` is a
symlink to it. It does not install or update Composer dependencies. Go components
and nginx are pinned by image digest in `compose.yml`.

## Start and log in

From the module checkout, with Docker Compose, Python 3 and OpenSSL installed:

```bash
./docker/oidfed/start.sh
```

Open **https://app.127.0.0.1.nip.io:9443/**. OFFA's OP picker should list
**SSP ML-DSA lab OP**. Select it and log in with **student / studentpass**.
You should return to the test app with the student's identity. `/claims` returns
that identity as JSON. The app has no published port: the TLS proxy checks
OFFA's session before forwarding a request and overwrites the identity headers.

The lab listens on loopback only. The existing manual lab on port 8443 is
independent and can remain running.

### TLS and DNS

The startup script creates a local CA and a certificate covering all four lab
hostnames under `build/oidfed-lab/pki/`. Import **`ca.crt`** into the browser's
trusted test CAs, or accept the certificate exception for the lab sites. Burp's
browser trusts Burp's interception CA; if upstream certificate verification is
enabled in Burp, trust the lab CA there too.

Containers trust the lab CA and verify HTTPS on Federation and OIDC fetches.
The browser and containers use the same entity IDs and ports. Public `nip.io`
DNS resolves the names to loopback on the host; Docker aliases resolve them to
the proxy inside the lab network. If your DNS blocks loopback answers, add these
four hostname resolutions in Burp (or your hosts file), each pointing to 127.0.0.1:

```text
ta.127.0.0.1.nip.io
op.127.0.0.1.nip.io
rp.127.0.0.1.nip.io
app.127.0.0.1.nip.io
```

The CA private key stays on the host; it is not mounted into the containers.
Certificates and generated configuration are ignored build artifacts.

## Hosts

| Role | URL |
|------|-----|
| Protected app | https://app.127.0.0.1.nip.io:9443/ |
| SSP OP discovery | https://op.127.0.0.1.nip.io:9443/.well-known/openid-configuration |
| OP Entity Configuration | https://op.127.0.0.1.nip.io:9443/.well-known/openid-federation |
| OFFA login | https://rp.127.0.0.1.nip.io:9443/login |
| RP Entity Configuration | https://rp.127.0.0.1.nip.io:9443/.well-known/openid-federation |
| Lighthouse Entity Configuration | https://ta.127.0.0.1.nip.io:9443/.well-known/openid-federation |
| Lighthouse subordinate statement | https://ta.127.0.0.1.nip.io:9443/fetch?sub=https%3A%2F%2Frp.127.0.0.1.nip.io%3A9443 |
| Lighthouse Admin API / docs | http://localhost:9763/api/v1/admin/docs |

Lighthouse admin credentials are **lab-admin / oidfed-lab-admin**. The Admin API
is on a separate loopback port and is blocked at the public TA proxy. SSP's
admin password is **mldsa-admin**; `employee / employeepass` has module
client-management permissions. These are local test credentials.

## Switch ML-DSA variants

The default is ML-DSA-44. Restart with another variant:

```bash
OIDFED_ALG=ML-DSA-65 ./docker/oidfed/start.sh
OIDFED_ALG=ML-DSA-87 ./docker/oidfed/start.sh
```

`OIDFED_ALG=RS256` provides a baseline with RSA at Lighthouse, OFFA and the OP's
protocol signing. In that baseline, SSP's Federation signing remains ML-DSA-44,
as inherited from the manual lab configuration.

For each ML-DSA mode, the chosen variant is used for Lighthouse's statements,
OFFA's Federation statements and OIDC signed requests, and SSP's Federation
statements, ID tokens and JWT access tokens. RSA remains configured in SSP's
protocol profile for Discovery compliance. OFFA explicitly allows the chosen
ML-DSA algorithm and RSA rather than relying on its default allow-list.

Each mode has separate persistent OP, Lighthouse and OFFA volumes. Switching
modes creates or reuses that mode's keys and databases. This deliberately avoids
confusing an immediate algorithm test with Lighthouse's scheduled key-rotation
behavior. Restarting expires this lab RP's automatic registration at SSP so the
next login resolves its metadata again. Existing enrollment is updated through
Lighthouse's metadata and JWKS APIs.

After switching modes, clear cookies for the lab domains or use a fresh browser
session. To force another password login, clear the SSP OP cookies as well as
OFFA's session cookie. The selected mode is recorded in the ignored `.env` file
so later Compose commands address the right state. Running `start.sh` without
`OIDFED_ALG` restores ML-DSA-44.

## Inspect traffic and algorithms

Browser traffic is visible in Burp: OFFA login, SSP authorization, the signed
Request Object, authentication and the code redirect. Federation fetches, token
exchange and UserInfo are server-to-server requests; a browser proxy does not
capture those. Inspect component logs for that side:

```bash
docker compose -f docker/oidfed/compose.yml logs -f offa op lighthouse proxy
```

The lab-only PHP output observer reports the actual protected JWT headers of
SSP token responses without changing the response or logging the token itself:

```bash
docker compose -f docker/oidfed/compose.yml logs op | grep OIDFED_LAB_SIGNING
```

Look for `id_token`, `access_token` and `statement` entries with the selected
`alg` and corresponding `kid`. Normal debug/access logs can contain signed
request parameters and test identity claims. The observer is enabled only in
this lab's PHP configuration; no module production code is changed.

Startup pins Lighthouse's public JWKS in `build/oidfed-lab/shared/ta-jwks.json`.
The OP and RP both use it as their trust-anchor key set. Bootstrap also saves
Entity Configuration snapshots there for inspection; these expire and are not
a live source of metadata.

## Stop and restart

```bash
docker compose -f docker/oidfed/compose.yml down
./docker/oidfed/start.sh
```

Stopping preserves keys and data. To deliberately delete the **currently
selected mode's** keys and databases, use `down -v` instead. This does not delete
other modes' volumes or the original port-8443 lab. Re-running startup regenerates
missing material and re-enrolls the entities. Old cookies and captured tokens
will no longer match regenerated state.

## Verification and limits

The setup was exercised with ML-DSA-44, -65 and -87: trusted HTTPS, Lighthouse
subordinate statements, OFFA's OP discovery, signed RP Request Objects, automatic
client registration, password login, code exchange and the protected app's
identity headers. SSP token-response observations confirm the actual signing
algorithm of ID and access tokens. These are interoperability checks between
the Go and PHP stacks, not external conformance certification or comprehensive
key-rotation/security testing.
The ML-DSA-44 check also confirmed that SSP rejects a modified RP Request
Object signature, and the startup/enrollment procedure was repeated with
existing state.

The known final subordinate-to-anchor signature-check limitation in the OpenID
library remains outside this lab setup. A passing login does not fix or validate
that missing negative case. See the module's ML-DSA compliance checklist.
