# ML-DSA support

This checklist covers ML-DSA signing and verification for OpenID Connect and
OpenID Federation in this module, using the support added to
`simplesamlphp/openid`. It does not include OpenID4VCI or DPoP unless their
profiles are separately confirmed to permit ML-DSA.

## Dependency and configuration

- [x] Set the `simplesamlphp/openid` dependency to a release or development
  revision that includes ML-DSA support, and document a reproducible Composer
  setup while that support is unreleased.
- [x] Confirm the OpenID library's ML-DSA algorithm names and runtime
  requirements, including PHP/OpenSSL provider support, against this module's
  supported environments. See the runtime requirements in
  `docs/2-oidc-installation.md`: PHP 8.4+, OpenSSL 3.5+ with an available ML-DSA
  provider, and a PHP-process capability check; PHP 8.3 remains supported for
  existing algorithms.
- [x] Allow the ML-DSA-44, ML-DSA-65, and ML-DSA-87 enum values in protocol and
  federation signing-key configuration; verify key loading and validation for
  each configured algorithm. The existing enum-based parser accepts them; add
  configuration examples and cover PEM loading, key IDs, signing/verification,
  invalid PEMs, and wrong-variant rejection when signing in `ModuleConfigMlDsaTest`.
- [x] Review discovery and advertised algorithm lists. Add ML-DSA only where
  the relevant OpenID Connect or Federation metadata/profile permits it; keep
  unrelated algorithm lists (including DPoP) accurate. OpenID JOSE services opt
  into runtime-supported variants; DPoP and credential lists remain unchanged.
  ID-token discovery includes configured ML-DSA keys when supported by the runtime.

## League OAuth2 Server key compatibility

- [x] Replace League's RSA/EC-only `CryptKey` with an unused `CryptKeyInterface`
  implementation whose getters throw. League requires the object but never reads
  its key material on the module's signing paths; signing and key validation remain
  with the OpenID library. Cover server initialization and all three ML-DSA variants
  for access-token signing and verification.

## OpenID Connect coverage

- [x] Implement the ML-DSA ID-token `at_hash` calculation using the OpenID token
  hash guide's SHAKE256 mapping, then enable ML-DSA in ID-token discovery and
  cover issuance through `IdTokenBuilder`.
- [x] Map applicable ML-DSA requirements to implementation and existing PHPUnit
  tests in `conformance-tests/rfc9964-mldsa-compliance.md`, following the PAR checklist.
  Distinguish module coverage, dependency evidence, deployment concerns and gaps.
- [x] Add focused coverage of authorization-code and refresh-grant orchestration
  for all three variants in the existing PHPUnit suite. The external conformance
  suite currently lacks complete ML-DSA verification support. `MlDsaGrantTest`
  redeems encrypted codes through the real server/grants, verifies ID/access
  tokens and `at_hash`, checks rotation, narrowed scopes and subject continuity,
  and rejects bad PKCE and grant replay. Storage and authentication-rule results
  are doubles; browser login and real client credential validation are not covered.
- [x] Verify the published OIDC JWKS includes the ML-DSA public key with the
  expected `kid`, `alg`, and public key parameters, and that consumers can
  verify tokens from it. `JwksControllerTest` checks actual JSON responses and
  verifies signatures using their public keys, including Federation keys.
- [x] Exercise configured ML-DSA key selection alongside existing RSA/EC
  keys, including multiple keys and rotation where supported.
  `MlDsaKeySelectionTest` covers defaults, explicit ID-token algorithms,
  missing-algorithm key refusal, and manual rollover with old keys retained in
  the published JWKS. It verifies both ID and access tokens for all variants.

## OpenID Federation coverage

- [x] Add focused PHPUnit coverage for signing Federation Entity Statements with
  ML-DSA-44, -65, and -87 and verifying them with the published Federation
  JWKS. `MlDsaEntityStatementTest` exercises the real controller, factories,
  PEM configuration, public JWKS responses and manual Federation-key rollover.
- [x] Check the Federation entity configuration and statement metadata expose
  the correct algorithm and key identifiers, and that trust-chain processing
  interoperates with ML-DSA-signed statements where supported.
  The same test covers mixed RSA/ML-DSA chains and metadata-policy application,
  plus altered signatures and unendorsed leaf keys. It explicitly verifies the
  final subordinate signature before invoking the library's chain builder;
  that builder alone does not validate this link. Remote resolution and
  independent implementation interoperability remain outside this coverage.

## Verification and documentation

- [x] Ensure a CI job requires an ML-DSA-capable runtime so positive crypto
  coverage cannot silently turn into skipped cases.
  `ml-dsa-tests` uses PHP 8.5 on Ubuntu 26.04, requires all three capability
  probes and runs the focused suite with `--fail-on-skipped`. Composer loads
  the remote OpenID development branch through its VCS repository.
  The dependency's local ML-DSA changes still need publishing to that branch
  before a hosted run can pass; no GitHub Actions run was performed locally.
- [x] Document ML-DSA key generation/configuration, runtime prerequisites,
  algorithm selection, and any interoperability limitations for OIDC and
  Federation operators.
  See `docs/2-oidc-installation.md` for generation of all variants, configuration,
  defaults versus client selection, manual rollover and interoperability limits.
- [x] Run the focused ML-DSA tests, then the full test, static-analysis, and
  coding-standard suites after the dependency and CI changes are final.
  Local verification on 2026-10-29 (PHP 8.5.10, OpenSSL 3.6.5): focused suite
  passed with 160 tests / 1,803 assertions and no skipped cases; full suite ran
  5,254 tests / 24,218 assertions with the existing unrelated `NAN` upstream
  timeout failure and seven deprecations. Psalm, full CodeSniffer and Rector
  dry-run passed. The CI probe also refused an unavailable provider, and all
  six documented key-generation pairs were generated and matched successfully.
  The existing database integration suite ran 80 cases / 112 assertions: SQLite
  cases passed; 54 PostgreSQL/MySQL cases errored because this PHP environment
  lacks enabled PDO drivers for them.
  These runs used the installed local OpenID working copy. The ignored lock
  file and vendor tree still reflect that installation; updating them from VCS
  must wait for the dependency's ML-DSA changes to be published.



Pull request notes:
- For testing: the conformance suite does not have ML-DSA support, so I took a similar approach to conformance-tests/rfc9126-par-compliance.md: tracking every MUST / MUST NOT / REQUIRED etc. from the specification and mapping them to unit tests. 
- ML-DSA support is only available with supported PHP and OpenSSL runtimes. This pull request is backwards compatible with runtimes that do not support it.
