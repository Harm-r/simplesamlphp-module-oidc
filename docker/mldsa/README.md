# Manual ML-DSA OP lab

From the module checkout:

```bash
docker compose -f docker/mldsa/compose.yml up -d --build
```

Open **https://localhost:8443/** in Burp's browser and accept the lab's
self-signed TLS certificate. The service binds only to the host's loopback
interface. It uses its own Compose project and Docker volume, independently of
the conformance setup.

This lab runs PHP 8.5 with OpenSSL 3.5+ and requires all three ML-DSA runtime
probes to succeed. It uses the module checkout's installed `vendor/` directory
and mounts the sibling `../openid` checkout, preserving the local Composer
symlink layout. Install the module's dependencies first. If OpenID is installed
as an ordinary VCS package instead of a symlink, the installed vendor copy is
what runs; changes in a sibling checkout then do not affect it. No Composer
install or update runs when the container starts.

## Try the flows

1. Choose an ID-token algorithm and click **Authorize with S256 PKCE**.
2. Log in as `student` with password `studentpass`.
3. On the callback page, click **Redeem authorization code**. This is a separate
   action so you can inspect or edit the token request in Burp.
4. Click **Refresh tokens** and **UserInfo** to exercise those requests.

All of those requests originate from the browser, so they can be captured in
Burp. Tokens and PKCE state are retained in this tab's session storage. **Clear
local tokens** removes them, but does not log out the SimpleSAMLphp session.
The decoded JWT display does not verify signatures.

The five seeded clients are public clients using S256 PKCE, without a client
secret. Their redirect URI is `https://localhost:8443/callback.html`:

| Client ID | ID-token signing algorithm |
|-----------|----------------------------|
| `burp-44` | `ML-DSA-44` |
| `burp-65` | `ML-DSA-65` |
| `burp-87` | `ML-DSA-87` |
| `burp-rsa` | `RS256` |
| `burp-default` | First configured protocol algorithm |

The OP defaults to ML-DSA-44 for access tokens and for `burp-default`. Choosing
another client changes the ID-token algorithm; it does not change the access-token
algorithm. To change the protocol default, recreate the service with one of
`RS256`, `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87`:

```bash
MLDSA_DEFAULT_ALG=RS256 docker compose -f docker/mldsa/compose.yml up -d
```

Choose `burp-44`, `burp-65` or `burp-87` in this mode to inspect an ML-DSA ID
token bound to an RSA access token. Return to the initial default with:

```bash
docker compose -f docker/mldsa/compose.yml up -d
```

The default ML-DSA variant also signs the Federation Entity Configuration.
When the protocol default is RSA, Federation defaults separately to ML-DSA-44.
RSA remains configured in every mode for OIDC discovery.

## Separate Go verifier

The [Go verifier](verifier/README.md) accepts a captured compact JWT and a public
JWK/JWKS JSON file using `lestrrat-go/jwx` and its ML-DSA adapter. Its README
includes signature-only and issuer/audience validation commands. The utility
is currently awaiting dependency download, compilation and positive/negative
verification checks; do not count it as tested interoperability evidence yet.

## Endpoints and keys

- Lab page: https://localhost:8443/
- OIDC discovery: https://localhost:8443/.well-known/openid-configuration
- Federation Entity Configuration: https://localhost:8443/.well-known/openid-federation
- Read `jwks_uri`, `authorization_endpoint`, `token_endpoint` and
  `userinfo_endpoint` from discovery for their exact paths.
- SimpleSAMLphp: https://localhost:8443/simplesaml/
- Admin password: `mldsa-admin`. The example user `employee / employeepass` has
  module client-management permissions.

The lab creates separate protocol and Federation RSA/ML-DSA pairs with explicit
key IDs in `/state/keys` inside the named Docker volume. Both profiles publish
through the JWKS endpoint; only Federation public keys appear in the Entity
Configuration's embedded JWKS. Private keys are not published or written into
the checkout. Credentials, keys and database contents are for this local lab.

Federation is enabled for inspecting self-signed Entity Configurations. No
trust anchor or authority hints are configured; this is not yet a multi-entity
Federation interoperability lab. VCI is disabled.

## Logs and lifecycle

```bash
docker compose -f docker/mldsa/compose.yml logs -f op
docker compose -f docker/mldsa/compose.yml down
```

Stopping preserves the keys, clients and SQLite database. Module, OpenID and
lab configuration changes are live mounts; changing the image recipe requires
`up -d --build`. Changing `MLDSA_DEFAULT_ALG` requires `up -d` with the new value.

For a deliberate fresh start, `docker compose -f docker/mldsa/compose.yml down
-v` deletes this lab's keys, sessions and database. Start again to regenerate
them. Previously captured tokens will no longer verify against the new keys.
