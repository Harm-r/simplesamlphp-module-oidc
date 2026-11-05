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

ML-DSA requires PHP 8.4+ and the `openssl` extension linked to OpenSSL 3.5+
with its ML-DSA provider enabled. OpenSSL includes ML-DSA in its default
provider; no separate OQS provider is needed. Other signing algorithms retain
the module's PHP 8.3 minimum. See the
[OpenSSL ML-DSA documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/).

This development checkout uses `https://github.com/Harm-r/openid.git` and
`dev-ml-dsa-support as 0.11.x-dev`, which requires `web-token/jwt-library`
`4.3.x-dev`. Install with `composer install`. To refresh an existing checkout,
run `composer update simplesamlphp/openid --with-all-dependencies`. Replace
these development dependencies with released versions before a stable release.

Check availability from the SimpleSAMLphp directory using the deployed PHP
binary, container and OpenSSL configuration. Check PHP-FPM/Apache separately
if its environment differs from the CLI:

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

The module accepts runtime-supported ML-DSA variants for OIDC, Federation and
DPoP. Credential proofs and credential Status Lists keep their existing
algorithm policy. DPoP clients supply their own proof keys; the server does
not need an ML-DSA signing key to accept those proofs.

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

From the SimpleSAMLphp directory, use OpenSSL 3.5+ to create separate protocol
and Federation keys. Generate only the pairs you plan to configure:

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

These commands create unencrypted PKCS#8 private PEMs. Keep `.key` files out
of source control and readable only by the service account. Each `.pub` file
must match its private key and algorithm; verify a signed token against the
published key after setup, since the loader does not check that the files match.

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

For Federation, enable `ModuleConfig::OPTION_FEDERATION_ENABLED` and add an
entry to `ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS` using the
`federation` filenames and a distinct `kid`. Use `MLDSA65` or `MLDSA87` with
the matching files for the other variants. Paths resolve under SimpleSAMLphp's
certificate directory; absolute paths are also accepted.

### Selecting ML-DSA and rolling keys

The first protocol key signs access tokens and supplies the default ID-token
algorithm. Clients can select an ID-token algorithm with
`id_token_signed_response_alg` set to `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`.
The module uses the first matching protocol key and rejects requests for an
algorithm with no configured key. ID-token discovery advertises configured,
runtime-supported algorithms.

Keep an RS256 protocol key for
[OIDC Discovery compliance](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
Put ML-DSA first only when your clients support AKP JWKs and that variant.
Federation uses its own first key; check compatibility with its trust framework
and participating implementations before switching. With Federation enabled,
the public JWKS includes both profiles; an Entity Configuration embeds only
Federation keys.

For rollover, place a new pair with a new `kid` first in the relevant list.
Retain the old pair until its signed artifacts have expired and consumers have
refreshed their cached keys. Retained entries need both PEM files. Removing
an entry withdraws its public key; rotation and retention are manual.

ML-DSA signatures are 2,420, 3,309 or 4,627 bytes before base64url encoding.
Check HTTP-header and storage limits before deployment. See the
[coverage checklist](../conformance-tests/rfc9964-mldsa-compliance.md) for test
commands, token-hash details and known Federation validation limits.

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
