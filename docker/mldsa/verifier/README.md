# Go ML-DSA JWT verifier

A command-line verifier using [lestrrat-go/jwx v4](https://github.com/lestrrat-go/jwx)
and its [ML-DSA adapter](https://github.com/jwx-go/mldsa), separate from the
module's PHP JOSE/OpenSSL signing path.

**Validation pending:** this utility has been written and formatted, but has
not yet been compiled or exercised. Dependency/documentation downloads were
blocked by the tooling's expired sign-in. Confirm the adapter registration and
run the positive/negative checks below before treating it as verification evidence.

Requires Go 1.26+ and internet access for the first dependency download.

1. Save the JSON from the lab's **JWKS** link to `/tmp/mldsa-jwks.json`. A single
   public AKP JWK is also accepted. Use JSON containing `kty`, `alg` and `pub`,
   rather than a PEM file.
2. Copy the compact JWT to `/tmp/mldsa-token.jwt`, without quotes, `Bearer`,
   Markdown escapes or extra line breaks inside the token.
3. From this directory:

```bash
go mod tidy
go run . -jwks /tmp/mldsa-jwks.json -token /tmp/mldsa-token.jwt \
  -issuer https://localhost:8443 -audience burp-44
```

Use the client ID that actually received the token for `-audience`. The lab's
other clients include `burp-65`, `burp-87`, `burp-rsa` and `burp-default`. Only
ML-DSA-signed JWTs are accepted; a client named `burp-rsa` can still receive an
ML-DSA access token when that is the OP default.

To check the signature of an expired captured token without validating claims:

```bash
go run . -jwks /tmp/mldsa-jwks.json -token /tmp/mldsa-token.jwt -signature-only
```

Or read the JWT from standard input:

```bash
go run . -jwks /tmp/mldsa-jwks.json -signature-only < /tmp/mldsa-token.jwt
```

The verifier allows only `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87`, requires a
protected `kid`, and selects exactly one matching public AKP key by `kid` and
`alg`. A directly supplied single JWK may omit its own `kid`. It uses the
trusted file you supplied; it does not follow key URLs from the token or send
tokens to an external verifier. Private JWK material is refused.

By default jwx validates time claims and any expected issuer/audience supplied
on the command line. This is not a complete OIDC or RFC 9068 profile validator:
it does not enforce all required claims, token type, nonce or `at_hash`.
`-signature-only` explicitly skips every claim check, including expiration.

Before relying on the result, verify a current token for each variant, then
change a payload/signature byte and confirm verification fails. A different
public key must fail too. Generate `go.sum` with `go mod tidy` and retain it
with the verifier once the dependency integration has been validated.
