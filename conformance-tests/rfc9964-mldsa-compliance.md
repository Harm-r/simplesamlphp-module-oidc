# ML-DSA — JOSE requirements and module coverage

This checklist follows [the PAR checklist](rfc9126-par-compliance.md): map
requirements to implementation and tests in the existing PHPUnit suite, and
record gaps explicitly. It covers the JOSE application of
[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html), plus the applicable
[OpenID token hash guide](https://openid.net/specs/openid-connect-token-hash-algorithms-1_0.html).
COSE and credential-profile enablement are outside this change. DPoP proofs
accept the runtime-supported ML-DSA variants.

Keep the tables in sync when changing keys, algorithm policy, publication or
token signing. This is an implementation checklist, not external certification
or a validation of the underlying cryptographic primitive.

Status values:

- **Met**: a module test exercises the behavior, using real cryptography where relevant.
- **Delegated**: implemented in the OpenID/JOSE dependencies; evidence and limits are identified.
- **Config**: depends on deployment or configured keys.
- **Gap**: missing coverage or implementation; not counted as verified.

Module tests below live in `tests/unit/src/`. Tests labeled **OpenID library**
live in that separate project's `tests/src/`; they are not automatically run by
this module's PHPUnit configuration. The installed development dependency must
contain the ML-DSA implementation documented in the installation guide.

## JOSE key representation and signing

| # | Requirement / spec reference | Status | Enforced in | Covered by test / evidence |
|---|------------------------------|--------|-------------|----------------------------|
| 1 | AKP requires `alg` and `pub`; public keys exclude `priv` (§3). | Met | OpenID `SignatureKeyPairFactory`; `JwksController` publishes public decorators. | `ModuleConfigMlDsaTest::testLoadsAndUsesConfiguredKeyPair`; `JwksControllerTest::testPublishesUsableMlDsaPublicKeysWithoutPrivateMaterial` checks the exact response members and verifies against the returned keys for protocol and federation profiles. |
| 2 | JWK key material uses base64url (§3). | Delegated | JOSE `AKPKey` PEM conversion and OpenID public-key validation. | OpenID library `Helpers/JwkTest::testRefusesWhatIsNotAPublicKey` includes non-canonical AKP encoding. Module publication tests verify the generated public key through the JOSE parser. |
| 3 | Private `priv` is a 32-byte seed (§4, §7.3). | Delegated | JOSE `AKPKey::seed()` before signing. | Seed validation belongs to the JOSE dependency. Module tests load PEM key pairs and verify a successful signing round trip; they do not independently test malformed raw seeds. |
| 4 | Use the registered variant and corresponding key/signature sizes (§5). | Met / delegated | OpenID enum, JOSE `MLDSA` and `AKPKey`. | `ModuleConfigMlDsaTest::testLoadsAndUsesConfiguredKeyPair` loads and uses each variant for protocol and federation configuration; `testRejectsKeyForAnotherAlgorithmWhenSigning` refuses a configured wrong variant. Raw size validation belongs to the dependencies. |
| 5 | Pure ML-DSA, empty context; no HashML-DSA substitution (§5, §7.2). | Delegated | JOSE `AKPKey::sign()` / `verify()` call OpenSSL without a digest or custom context. | Source inspection of the dependency; real sign/verify tests cover interoperability within this stack. No independent FIPS algorithm/context vector is asserted by the module. |
| 6 | Thumbprint input contains ordered `alg`, `kty`, `pub` (§6). | Met | OpenID `SignatureKeyPairFactory` and JOSE JWK thumbprints. | `ModuleConfigMlDsaTest::testDerivesKeyIdFromPublicKey` independently constructs canonical JSON, hashes and encodes it, then compares the generated key ID. |
| 7 | Validate algorithm-specific parameters before use (§7.3). | Delegated | JOSE `MLDSA::sign()` / `verify()` and `AKPKey::checkKey()`. | Module tests cover malformed PEMs and configured wrong variants. OpenID library `Helpers/JwkTest` covers malformed public parameters. Raw private-key and FIPS encoding validation remain dependency responsibilities. |
| 8 | Protect seeds like expanded private keys (§7.1). | Config | Deployment key storage and access controls. | No unit test establishes filesystem, secret-store or backup security. |
| 9 | Consider inconsistent public/private parameters (§7.4 security consideration). | Delegated / gap | JOSE checks consistency inside one private AKP key. | No module test directly exercises inconsistent raw JWKs. Separate configured private/public PEM files are not compared during configuration loading; positive tests verify a correctly paired configuration, not rejection of mismatched files. |

Expected public-key/signature lengths in bytes (RFC 9964 §5):

| Variant | Public key | Signature |
|---------|------------|-----------|
| ML-DSA-44 | 1312 | 2420 |
| ML-DSA-65 | 1952 | 3309 |
| ML-DSA-87 | 2592 | 4627 |

The seed remains 32 bytes for each variant. Signature sizes here are decoded
bytes, before JWS base64url encoding.

## Module behavior and OpenID token hashes

| # | Requirement / behavior | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 10 | Select SHAKE256, request 64 output bytes, retain the first 32, then unpadded base64url for ML-DSA `at_hash` (token hash guide §2, table 1). | Met | `IdTokenBuilder::generateAccessTokenHash`, using phpseclib `shake256-512`. | `IdTokenBuilderTest::testGeneratesMlDsaAccessTokenHash`: guide §3 vector, empty input, `abc`, and a multi-block input, for each variant. The hash is of the access-token string, not a prehash used for signing. |
| 11 | ID-token signing and `at_hash` use the selected ID-token algorithm. | Met | `IdTokenBuilder::buildFor`. | `IdTokenBuilderTest::testIssuesMlDsaIdTokenWithAccessTokenHash`; `MlDsaKeySelectionTest::testSelectsRequestedAlgorithmFromMixedConfiguredKeys` verifies real RSA/EC/ML-DSA selection, including ML-DSA ID tokens paired with RSA access tokens. Hash correctness and ID-token hash issuance are checked independently in `IdTokenBuilderTest`. |
| 12 | JWT access tokens use the configured protocol key and algorithm. | Met | `AccessTokenEntity::convertToJWT`, OpenID `JwtAccessTokenFactory`. | `AccessTokenEntityTest::testMintsMlDsaAccessTokenWithLeagueKey` signs, parses and verifies all variants while carrying the unused League key. |
| 13 | Signature verification rejects wrong keys and changed content. | Met / delegated | OpenID JWS verifier and JOSE `MLDSA`. | Library `MLDSATest` covers wrong keys and altered signatures. Module `BearerTokenValidatorTest::testMlDsaProofWithAccessTokenBinding` covers tampered DPoP signatures and valid proofs using a key different from the access-token binding. Configuration tests retain one positive signing/verification round trip. |
| 14 | Advertise supported ID-token algorithms; keep RS256 for OIDC Discovery compliance (§3). | Met / config | `OpMetadataService` intersects configured protocol algorithms with runtime support. | `OpMetadataServiceTest::testAdvertisesMlDsaOnlyForImplementedOpenIdUses`, `testOmitsUnavailableAlgorithmsFromIdTokenDiscovery`. Operators must retain an RS256 protocol key; configuration does not enforce that requirement. |
| 15 | ML-DSA DPoP acceptance and advertising match runtime support; credential algorithm policy stays unchanged. | Met | `ModuleConfig::getSupportedAlgorithms` opt-in; OpenID factories request it. | `ModuleConfigMlDsaTest::testMlDsaIsOptInAndDependsOnRuntimeSupport`; `OpMetadataServiceTest`; OpenID factory tests assert the opt-in argument. `DpopProofVerifierTest::testMlDsaProofAtTokenEndpointAndReplay` checks verification, SHA-256 AKP thumbprints and replay; `BearerTokenValidatorTest::testMlDsaProofWithAccessTokenBinding` checks valid binding, wrong keys, tampered signatures and incorrect `ath` for all variants. |
| 16 | Missing runtime support is detected. | Met / config | OpenID enum runtime probe; module algorithm policy. | `testMlDsaIsOptInAndDependsOnRuntimeSupport`; OpenID library `Algorithms/SignatureAlgorithmEnumTest::testMLDSARuntimeSupport` and `MLDSATest::testExplicitConfigurationFailsClearlyWhenRuntimeDoesNotSupportMLDSA`. Positive crypto cases skip when unavailable. |
| 17 | League server initialization does not parse protocol keys as RSA/EC. | Met | `UnusedLeagueSigningKey`, service wiring and factory interface types. | `AuthorizationServerFactoryTest::testBuildsWithoutReadingLeagueKeyMaterial`; `UnusedLeagueSigningKeyTest::testRejectsKeyMaterialAccess`. |
| 18 | Authorization-code and refresh grants emit valid ML-DSA ID/access tokens. | Met | `AuthorizationServer`, `AuthCodeGrant`, `RefreshTokenGrant`, real token factories and response serialization. | `MlDsaGrantTest::testRedeemsAuthorizationCodeAndRefreshesMlDsaTokens` covers encrypted-code redemption, refresh and verification of the resulting tokens for every variant, with the throwing League-key placeholder. Independent hash correctness is covered by `IdTokenBuilderTest`; generic PKCE and grant-replay checks remain in the existing grant tests. |
| 19 | Local default-key policy and explicit ID-token algorithm selection stay distinct. | Met | Configured bag order; `AccessTokenEntity::convertToJWT`; `IdTokenBuilder::buildFor`. | `MlDsaKeySelectionTest::testFirstConfiguredKeyControlsDefaultSigning` exercises RSA, EC and ML-DSA defaults and reverses the returned JWKS for verification. `testDoesNotFallBackWhenRequestedAlgorithmHasNoConfiguredKey` refuses a missing algorithm rather than substituting RSA. First-configured-key preference is module policy, not a JWKS ordering requirement. |
| 20 | Manual signing-key rollover retains old verification keys during transition (OIDC Core §10.1.1). | Met / config | Protocol key configuration, `kid`, and `JwksController`. | `MlDsaKeySelectionTest::testRotatesMlDsaKeyWhileRetainingOldVerificationKey` covers every variant: two distinct keys for one algorithm, new-default and explicit selection, real publication, verification of old/new ID and access tokens, and failure of old tokens after key withdrawal. No automatic rotation or retention duration is implemented. |

OIDC discovery requirements: [OpenID Connect Discovery §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
Key rollover: [OIDC Core §10.1.1](https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys).
JWKS ordering: [RFC 7517 §5.1](https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1).
Client algorithm selection: [OIDC Registration §2](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata).
The token hash guide is an implementer's guide; its mapping is not itself part
of RFC 9964. Existing RSA/EC and EdDSA behavior is outside the new hash mapping.

## OpenID Federation coverage

These cases cover the module's use of the OpenID Federation library; RFC 9964
itself does not define Federation metadata or trust-chain policy. Algorithm
acceptance also depends on the federation's trust framework.

| # | Behavior | Status | Enforced in | Covered by test |
|---|----------|--------|-------------|-----------------|
| 21 | Entity Configurations use the configured Federation key and publish usable public keys. | Met | `EntityStatementController`, `FederationFactory`, `JwksFactory`, `JwksController`. | `MlDsaEntityStatementTest::testPublishesVerifiableFederationConfiguration` checks all variants through the real controller: content type, protected `typ`/`alg`/`kid`, issuer/subject/timestamps, authority hints, exact public AKP members, self-verification and verification against the published JWKS. Real OP metadata retains protocol-key algorithms and advertises ML-DSA for DPoP. |
| 22 | Federation key selection and manual rollover remain separate from protocol-key configuration. | Met / config | First Federation key signs; all configured Federation public keys are published. | `testRotatesFederationKeysIndependentlyOfProtocolKeys` checks ML-DSA and EC defaults, two ML-DSA keys, retained old/new signatures and refusal after old-key withdrawal for all variants. The protocol key remains RSA throughout. |
| 23 | Mixed RSA/ML-DSA trust-chain processing and metadata policies. | Delegated / not covered here | OpenID Entity Statement and trust-chain factories. | The module suite tests controller-produced Entity Configurations and key rollover, not library-only trust-chain assembly or policy processing. Complete remote validation remains outside this coverage; see below. |

## Remaining coverage and evidence limits

- The grant test starts with a stored, encrypted authorization-code fixture.
  Repositories, client authentication/rule results and logging are doubles;
  browser login, credential checking, routing and database transactions are not
  exercised. Token construction, signing and grant execution are real.
- **Gap:** the installed OpenID library's `TrustChain::addTrustAnchor` verifies
  the anchor's self-signature but does not verify the final subordinate
  statement with the anchor's keys. Controller publication tests do not establish
  that the library's chain builder or remote resolver completely authenticates
  a chain. This dependency limitation is outside the module's ML-DSA changes.
- Federation tests cover local Entity Configuration publication and key rollover,
  not HTTP fetches, trust-anchor distribution, remote caches, metadata-policy
  processing or another implementation's trust framework.
- Manual protocol and Federation key rollover is tested by constructing a new configuration
  instance. Old keys remain full configured pairs because the current loader
  expects both PEM files. There is no automatic retention scheduler or test of
  remote relying-party JWKS cache refresh behavior.
- The existing `basic-tests` PHP 8.5 entry uses Ubuntu 26.04, installs
  the remote OpenID development dependency, requires all three
  runtime probes to pass and runs the full test suite.
  The general PHP matrix still permits unavailable crypto cases to skip.
  The dependency's ML-DSA changes must be present on its remote development
  branch before that job can pass; local sibling modifications are not
  available to GitHub Actions.
- **External suite limitation:** the reviewed `release-v5.3.1` and default-branch
  snapshot `23353b36957d6466010de767c812d2c91ed37638` recognize the algorithm names
  but do not provide complete AKP/signature/token-hash support. See the suite's
  [JWSUtil](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.1/src/main/java/net/openid/conformance/util/JWSUtil.java),
  [JWKUtil](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.1/src/main/java/net/openid/conformance/util/JWKUtil.java)
  and [JWAUtil](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.1/src/main/java/net/openid/conformance/util/JWAUtil.java).
  Existing RSA conformance runs remain protocol regression coverage.
- Crypto round trips use the same underlying implementation on both sides.
  They do not establish independent implementation interoperability or FIPS validation.

## Run the mapped module tests

From the module checkout:

```bash
vendor/bin/phpunit --no-coverage --fail-on-skipped --filter 'MlDsaEntityStatementTest|MlDsaKeySelectionTest|MlDsaGrantTest|ModuleConfigMlDsaTest|IdTokenBuilderTest|AccessTokenEntityTest|JwksControllerTest|OpMetadataServiceTest|UnusedLeagueSigningKeyTest|AuthorizationServerFactoryTest'
```

Check that `SignatureAlgorithmEnum::MLDSA44->isSupported()` is true before
calling the run positive ML-DSA evidence. PHP 8.4+ and an available OpenSSL
ML-DSA provider are required, as detailed in the installation guide. A passing
run consisting only of skipped crypto cases does not establish signing support.
