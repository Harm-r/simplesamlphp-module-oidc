# OIDC Module - Installation

This guide walks you through installing, enabling, and preparing the OIDC
module in SimpleSAMLphp.

## Requirements

- SimpleSAMLphp 2.5.3.1 or newer. This is a Composer requirement, so an older
installation refuses the module rather than failing once it runs.
- PHP 8.3 or newer.
- The PHP extensions `curl`, `json`, `openssl`, `pdo` and `gmp`. Only `gmp` is
likely to be missing: it is not required by the module directly but by
`simplesamlphp/openid`, which the module depends on, so Composer refuses the
installation without it. On Debian and Ubuntu it is `php-gmp`.

### ML-DSA runtime requirements

The OpenID library exposes these exact enum cases and algorithm identifiers:

| `SignatureAlgorithmEnum` case | Algorithm identifier (`alg`) |
| --- | --- |
| `MLDSA44` | `ML-DSA-44` |
| `MLDSA65` | `ML-DSA-65` |
| `MLDSA87` | `ML-DSA-87` |

The current development dependency is `simplesamlphp/openid`'s
`dev-ml-dsa-support` branch, which requires `web-token/jwt-library`'s
`4.3.x-dev` branch. Installing these dependencies does not by itself make
ML-DSA available in PHP.

ML-DSA requires PHP 8.4 or newer, the `openssl` extension, and an OpenSSL
library providing ML-DSA. OpenSSL added ML-DSA in 3.5 and includes all three
variants in its default provider; no separate OQS provider is needed for that
implementation. The provider must be available to the PHP process. Custom
OpenSSL provider configuration can disable it even on a sufficiently recent
OpenSSL installation. See the
[OpenSSL ML-DSA documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
and [default provider documentation](https://docs.openssl.org/3.5/man7/OSSL_PROVIDER-default/).

The module's Composer requirement remains PHP `^8.3`. Its CI matrix covers
PHP 8.3, 8.4 and 8.5, with the following ML-DSA requirements:

| PHP environment | ML-DSA availability |
| --- | --- |
| 8.3 | Unavailable; the upstream library requires PHP 8.4+ for signing and verification without a digest. |
| 8.4 or 8.5, without an available ML-DSA provider | Unavailable, regardless of successful Composer installation. |
| 8.4 or 8.5, with an available ML-DSA provider | Supported by the library; check availability in the deployed PHP process. |

Existing RSA/EC configurations retain their existing runtime requirements.
The dedicated `ml-dsa-tests` CI job uses PHP 8.5 on
[Ubuntu 26.04](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2604-Readme.md) and requires
all three runtime probes to pass before running the focused tests with
`--fail-on-skipped`. The general PHP matrix still permits unavailable crypto
cases to skip. The Docker image inherits PHP/OpenSSL from its selected base
image, so a successful Docker build alone does not establish ML-DSA availability.

Run this check from the SimpleSAMLphp installation directory:

```bash
php <<'PHP'
<?php
require 'vendor/autoload.php';

use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

$available = true;
foreach (['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as $name) {
    $supported = SignatureAlgorithmEnum::tryFrom($name)?->isSupported() ?? false;
    printf("%s: %s\n", $name, $supported ? 'available' : 'unavailable');
    $available = $available && $supported;
}
exit($available ? 0 : 1);
PHP
```

Use the same PHP binary, container and OpenSSL configuration as the deployed
service. If CLI and PHP-FPM/Apache use different environments, check the
service's PHP process as well. `openssl version` describes the command-line
tool, while `OPENSSL_VERSION_TEXT` describes PHP's build headers; neither is
the capability check used by the library.

`isSupported()` uses the upstream runtime probe, which tries to load an ML-DSA
key through PHP's OpenSSL extension. It does not enable the algorithm in the
module or validate a configured signing key. Explicitly constructing an
unavailable algorithm with `instance()` throws
`Jose\Component\Core\Exception\MissingDependencyException`; there is no
automatic fallback to RSA/EC. See the
[OpenID library's runtime documentation](https://github.com/simplesamlphp/openid/blob/ml-dsa-support/docs/2-installation.md#ml-dsa-runtime-support).

### Development dependency setup

Until the OpenID changes are released, this checkout's `composer.json` uses
`https://github.com/Harm-r/openid.git` as a VCS repository and requires
`dev-ml-dsa-support as 0.11.x-dev`. Run `composer install` from the module
checkout; a sibling OpenID checkout is not required.

The OpenID development branch itself must contain the ML-DSA changes and its
`web-token/jwt-library` dependency on `4.3.x-dev`. Keep the module's development
stability settings while using these unreleased dependencies. Record the
resolved Composer lock file and `composer show simplesamlphp/openid` output
with test results: a branch name alone does not pin a revision. CI records
that dependency information as well.

The OpenID ML-DSA changes must be committed and pushed to the remote branch
before a fresh install or CI can use them. Local modifications in a previous
path-based installation are not fetched from the VCS repository. When switching
an existing development checkout, update its ignored lock file with
`composer update simplesamlphp/openid --with-all-dependencies` after those
changes are published. Replace the development repository and constraint with
the released package before distributing a stable module release.

### ML-DSA algorithm advertisement

ML-DSA is registered for JOSE by [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html#section-5).
The module includes its three variants in the OpenID JOSE services only when
the runtime availability check succeeds. Their use in a particular federation
also depends on that federation's trust framework and participating
implementations, as described in
[OpenID Federation section 3](https://openid.net/specs/openid-federation-1_0.html#section-3).

| Metadata or use | ML-DSA policy |
| --- | --- |
| `request_object_signing_alg_values_supported` | Advertise runtime-supported variants. |
| `token_endpoint_auth_signing_alg_values_supported` | Advertise runtime-supported variants for client assertions. |
| `introspection_endpoint_auth_signing_alg_values_supported` | Same as token endpoint authentication, while introspection is enabled. |
| `id_token_signing_alg_values_supported` | Advertise algorithms from configured protocol keys that are supported by the runtime, including ML-DSA. |
| Federation entity statements, generic JWS/JWKS and JWT access tokens | Enable runtime-supported variants; signing still requires a configured key. |
| DPoP, credential proofs and credential Status Lists | Keep the existing algorithm policy; this change does not enable ML-DSA there. |

For ML-DSA ID tokens, `at_hash` uses SHAKE256 with 64 bytes of output,
keeps the first 32 bytes, and base64url-encodes them without padding, following
the [OpenID token hash implementer's guide](https://openid.net/specs/openid-connect-token-hash-algorithms-1_0.html#section-2).
The module uses `phpseclib/phpseclib` for SHAKE256 because PHP's built-in hash
API does not expose it and the OpenSSL digest API cannot select its output
length. Existing RSA/EC and EdDSA hash calculations are unchanged.
OIDC Discovery requires `RS256` in the ID-token algorithm list, so retain an
RS256 protocol key for [Discovery compliance](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

Keeping DPoP unchanged is a scope and local-policy decision, rather than a claim
that ML-DSA is forbidden by DPoP. [RFC 9449 section 4.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3)
requires an asymmetric registered algorithm that the application supports and
accepts under its local policy.

## 1. Install the module

Run:

```bash
composer require simplesamlphp/simplesamlphp-module-oidc
```

## 2. Configure the module

Copy the configuration template into your SimpleSAMLphp config directory
and review all options:

```bash
cp modules/oidc/config/module_oidc.php.dist config/module_oidc.php
```

## 3. Configure the database

The module uses SimpleSAMLphp's database feature to store Access and
Refresh tokens, user data, and other artifacts. Edit `config/config.php`
and ensure at least the following parameters are set:

```php
'database.dsn' => 'mysql:host=server;dbname=simplesamlphp;charset=utf8',
'database.username' => 'user',
'database.password' => 'password',
```

Note: SQLite, PostgreSQL, and MySQL are supported.

## 4. Create signature key pairs

In order to sign JWS artifacts (ID Tokens, Entity Statements, Verifiable
Credentials, etc.), you must create a public / private key pair for each
signature algorithm that you want to support. You should use different
keys for protocol (Connect), Federation and Verifiable Credential (VCI)
operations. You must have at least one algorithm / key-pair for protocol
(Connect), and for Federation and VCI if you use those features.

Create the key pairs that your `config/module_oidc.php` actually refers to, and
no others. As distributed, that file activates a single protocol (Connect) key
pair, `RS256` with `oidc_module_connect_rsa_01`, so following the RSA
instructions below is enough to get the module running. The other algorithms
shown here are examples that ship commented out; uncomment an entry only once
its key pair exists.

Getting that wrong is not a partial failure. Every activated key pair is
resolved before any JWS is signed, so an entry naming a key file that is not
there stops the module from signing at all, rather than only disabling the
algorithm that entry describes.

Federation key pairs are read only when Federation is enabled. VCI ships with an
`ES256` entry rather than an RSA one, so enabling VCI means creating the EC key
pair from the section below. Keep that key pair even if you later disable VCI:
Status Lists continue to be served so that credentials you have already issued
stay verifiable, and they are signed with it.

### RSA key pair generation, for `RS256/384/512` and `PS256/384/512` algorithms

Generate private keys without a password:

```bash
openssl genrsa -out cert/oidc_module_connect_rsa_01.key 3072
openssl genrsa -out cert/oidc_module_federation_rsa_01.key 3072
openssl genrsa -out cert/oidc_module_vci_rsa_01.key 3072
```

Generate private keys with a password:

```bash
openssl genrsa -passout pass:somePassword -out cert/oidc_module_connect_rsa_01.key 3072
openssl genrsa -passout pass:somePassword -out cert/oidc_module_federation_rsa_01.key 3072
openssl genrsa -passout pass:somePassword -out cert/oidc_module_vci_rsa_01.key 3072
```

Extract public keys:

Without password:

```bash
openssl rsa -in cert/oidc_module_connect_rsa_01.key -pubout -out cert/oidc_module_connect_rsa_01.pub
openssl rsa -in cert/oidc_module_federation_rsa_01.key -pubout -out cert/oidc_module_federation_rsa_01.pub
openssl rsa -in cert/oidc_module_vci_rsa_01.key -pubout -out cert/oidc_module_vci_rsa_01.pub
```

With a password:

```bash
openssl rsa -in cert/oidc_module_connect_rsa_01.key -passin pass:somePassword -pubout -out cert/oidc_module_connect_rsa_01.pub
openssl rsa -in cert/oidc_module_federation_rsa_01.key -passin pass:somePassword -pubout -out cert/oidc_module_federation_rsa_01.pub
openssl rsa -in cert/oidc_module_vci_rsa_01.key -passin pass:somePassword -pubout -out cert/oidc_module_vci_rsa_01.pub
```

Enter algorithm, key file names, and a password (if used) in `config/module_oidc.php` accordingly.

### EC key pair generation, per curve for different algorithms

Use these if you prefer Elliptic Curve Cryptography (ECC). Since each key-pair
option is a list, EC keys can replace the RSA ones or be advertised alongside
them, which is what the commented-out `ES256` example in the distributed
configuration does.

Generate private EC P‑256 keys without a password, usable for `ES256` algorithm:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out cert/oidc_module_connect_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 -noout -out cert/oidc_module_federation_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 -noout -out cert/oidc_module_vci_ec_p256_01.key
```

Generate private EC P‑256 keys with a password, usable for `ES256` algorithm:

```bash
openssl ecparam -genkey -name prime256v1 | openssl ec -AES-128-CBC -passout pass:somePassword -out cert/oidc_module_connect_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 | openssl ec -AES-128-CBC -passout pass:somePassword -out cert/oidc_module_federation_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 | openssl ec -AES-128-CBC -passout pass:somePassword -out cert/oidc_module_vci_ec_p256_01.key
```

Extract public keys:

Without password:

```bash
openssl ec -in cert/oidc_module_connect_ec_p256_01.key -pubout -out cert/oidc_module_connect_ec_p256_01.pub
openssl ec -in cert/oidc_module_federation_ec_p256_01.key -pubout -out cert/oidc_module_federation_ec_p256_01.pub
openssl ec -in cert/oidc_module_vci_ec_p256_01.key -pubout -out cert/oidc_module_vci_ec_p256_01.pub
```

With a password:

```bash
openssl ec -in cert/oidc_module_connect_ec_p256_01.key -passin pass:somePassword -pubout -out cert/oidc_module_connect_ec_p256_01.pub
openssl ec -in cert/oidc_module_federation_ec_p256_01.key -passin pass:somePassword -pubout -out cert/oidc_module_federation_ec_p256_01.pub
openssl ec -in cert/oidc_module_vci_ec_p256_01.key -passin pass:somePassword -pubout -out cert/oidc_module_vci_ec_p256_01.pub
```

For other curves, replace the `-name` option value depending on which
algorithm you want to support:

- `-name secp384r1`: usable for `ES384` algorithm
- `-name secp521r1`: usable for `ES512` algorithm

Enter algorithm, key file names, and a password (if used) in `config/module_oidc.php` accordingly.

### Ed25519 key pair generation, for `EdDSA` algorithm

Generate private keys without a password:

```bash
openssl genpkey -algorithm ED25519 -out cert/oidc_module_connect_ed25519_01.key
openssl genpkey -algorithm ED25519 -out cert/oidc_module_federation_ed25519_01.key
openssl genpkey -algorithm ED25519 -out cert/oidc_module_vci_ed25519_01.key
```

Generate private keys with a password:

```bash
openssl genpkey -algorithm ED25519 -AES-128-CBC -pass pass:somePassword -out cert/oidc_module_connect_ed25519_01.key
openssl genpkey -algorithm ED25519 -AES-128-CBC -pass pass:somePassword -out cert/oidc_module_federation_ed25519_01.key
openssl genpkey -algorithm ED25519 -AES-128-CBC -pass pass:somePassword -out cert/oidc_module_vci_ed25519_01.key
```

Extract public keys:

Without password:

```bash
openssl pkey -in cert/oidc_module_connect_ed25519_01.key -pubout -out cert/oidc_module_connect_ed25519_01.pub
openssl pkey -in cert/oidc_module_federation_ed25519_01.key -pubout -out cert/oidc_module_federation_ed25519_01.pub
openssl pkey -in cert/oidc_module_vci_ed25519_01.key -pubout -out cert/oidc_module_vci_ed25519_01.pub
```

With a password:

```bash
openssl pkey -in cert/oidc_module_connect_ed25519_01.key -passin pass:somePassword -pubout -out cert/oidc_module_connect_ed25519_01.pub
openssl pkey -in cert/oidc_module_federation_ed25519_01.key -passin pass:somePassword -pubout -out cert/oidc_module_federation_ed25519_01.pub
openssl pkey -in cert/oidc_module_vci_ed25519_01.key -passin pass:somePassword -pubout -out cert/oidc_module_vci_ed25519_01.pub
```

Enter algorithm, key file names, and a password (if used) in `config/module_oidc.php` accordingly.

### ML-DSA key generation, for `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87`

Use an OpenSSL 3.5+ command-line tool with ML-DSA available. The commands below
create separate protocol and Federation pairs for all variants, using names
that match the `MLDSA44` examples in the distributed configuration. Generate
only the pairs you intend to configure, in your SimpleSAMLphp directory:

```bash
umask 077
for profile in connect federation; do
    for variant in 44 65 87; do
        key="cert/oidc_module_${profile}_mldsa${variant}_01"
        openssl genpkey -algorithm "ML-DSA-${variant}" -out "${key}.key"
        openssl pkey -in "${key}.key" -pubout -out "${key}.pub"
    done
done
```

The `.key` file contains the private key and the `.pub` file contains the
public key. Give the service account read access to its private keys and keep
those files out of source control. These commands produce unencrypted PKCS#8
private PEMs, which the module tests exercise. A configured public PEM must
match the private PEM and algorithm; loading the two files does not itself
prove they form a pair, so verify a signed artifact against the published key.

Add this entry to `ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS` in
`config/module_oidc.php`, alongside the existing RSA entry:

```php
[
    ModuleConfig::KEY_ALGORITHM => \SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum::MLDSA44,
    ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module_connect_mldsa44_01.key',
    ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'oidc_module_connect_mldsa44_01.pub',
    ModuleConfig::KEY_KEY_ID => 'mldsa44-connect-signing-key-01',
],
```

For Federation, enable `ModuleConfig::OPTION_FEDERATION_ENABLED` and add the
corresponding entry to `ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS`,
using the `federation` filenames and a distinct `kid`, such as
`mldsa44-federation-signing-key-01`. For the other variants, change the enum to
`MLDSA65` or `MLDSA87` and use the matching files and key ID. Key paths resolve
under SimpleSAMLphp's certificate directory; absolute paths are also accepted.
Do not add these keys to the VCI profile for this feature.

### Selecting ML-DSA and rolling keys

The first protocol key signs JWT access tokens and ID tokens whose client has
not selected an algorithm. Adding ML-DSA after RSA therefore publishes its key
and enables explicit ID-token selection while keeping RSA as the default.
Set the client's `id_token_signed_response_alg` metadata to `ML-DSA-44`,
`ML-DSA-65` or `ML-DSA-87` to select that ID-token algorithm. Selection takes the
first protocol key matching the requested algorithm; it fails if no such key
is configured. The ID-token algorithm determines `at_hash`, even when its
access token uses another algorithm.

To use ML-DSA for default protocol signing, put its entry first and retain the
RSA entry for Discovery compliance. Federation separately uses the first
Federation key to sign Entity Configurations. Protocol-key order does not
select the Federation signing key, and JWKS order is not a preference list.
When Federation is enabled, the public JWKS endpoint contains both profiles;
the Entity Configuration's embedded `jwks` contains Federation keys only.

For manual rollover, generate a new pair with a new `kid`, place it first in
the applicable list and retain the old pair. Both public keys remain published
while new artifacts use the new key. Keep the old pair until artifacts signed
with it have expired and consumers have had time to refresh their cached keys.
The current loader requires both PEM files for each retained entry. Removing
an entry withdraws its public key; the module does not schedule rotation or
retention automatically.

### Interoperability limits

Confirm that clients and federation participants understand AKP JWKs and the
selected ML-DSA variant before changing default signing. An RSA key elsewhere
in the JWKS does not let a consumer verify an ML-DSA signature. Signatures are
larger (2,420, 3,309 or 4,627 bytes before base64url encoding), so check token,
HTTP-header and storage limits along the deployed path. For Federation,
algorithm acceptance also depends on the trust framework.

The existing external conformance suite does not fully verify ML-DSA keys,
signatures and token hashes. The module's PHPUnit cases exercise real signing,
verification, grants and Federation metadata, using the same crypto stack on
both sides. They do not establish independent implementation interoperability.
The installed OpenID library's chain builder also omits the final
subordinate-to-anchor signature check; the focused chain tests perform it
explicitly. This feature does not fix that dependency limitation or establish
complete remote trust-chain validation. See the
[coverage checklist](../conformance-tests/rfc9964-mldsa-compliance.md) for the
mapped tests, runtime gate and remaining limits.

## 5. Enable the module

Edit `config/config.php` and enable `oidc`:

```php
'module.enable' => [
    'exampleauth' => false,
    'core' => true,
    'admin' => true,
    'saml' => true,
    // enable oidc module
    'oidc' => true,
],
```

## 6. Run database migrations

Run the built-in migrations to create required tables.

Option A: Web UI

- Go to the admin area, then `OIDC` > `Database Migrations` and click the
  available button.

Option B: Command line

```bash
php modules/oidc/bin/install.php
```

## 7. Next steps

- Configure caches, endpoints, and other options:
  see [Configuration](3-oidc-configuration.md)
- Administer clients from the UI:
  see [Relying Party (RP) Administration](3-oidc-configuration.md#relying-party-rp-administration)
