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

The RFC inventory below is separate from the module/profile regression tests; 
passing the latter is not a claim of complete RFC, FIPS or OpenID profile conformance.

Status values:

- **Met**: a module test exercises the behavior, using real cryptography where relevant.
- **Delegated**: implemented in the OpenID/JOSE dependencies; evidence and limits are identified.
- **Config**: depends on deployment or configured keys.
- **Gap**: missing coverage or implementation; not counted as verified.
- **Out of scope**: not implemented or assessed by this JOSE module.

Statuses may be combined: a tested integration can still delegate primitive
validation or require deployment configuration. Delegated means source evidence,
not independent cryptographic validation.

Module tests below live in `tests/unit/src/`. Tests labeled **OpenID library**
live in that separate project's `tests/src/`; they are not automatically run by
this module's PHPUnit configuration. The installed development dependency must
contain the ML-DSA implementation documented in the installation guide.

## RFC 9964 requirement inventory

This inventory includes every explicit implementation obligation in the RFC's
body, including all uppercase REQUIRED, MUST and MUST NOT clauses, and the
additional encoding rules and security considerations. Requirements inherited
from referenced RFCs/FIPS are identified, not exhaustively reproduced. COSE
requirements are accounted for separately below; they are not claimed as met.
The RFC does not mandate implementing all three optional JOSE algorithms.

| ID | Requirement / spec reference | Status | Implementation and current evidence |
|---|---|---|---|
| R1 | AKP `alg` is required (§3). | Met / delegated | OpenID/JOSE key loading and validation retain `alg`. `ModuleConfigMlDsaTest::testLoadsAndUsesConfiguredKeyPair` and `JwksControllerTest::testPublishesUsableMlDsaPublicKeysWithoutPrivateMaterial` check all variants. Missing-parameter rejection is in OpenID library `Helpers/JwkTest::testRefusesWhatIsNotAPublicKey`. |
| R2 | AKP `pub` is required (§3). | Met / delegated | The same module tests check publication and usable public keys; the OpenID helper tests reject missing public material. |
| R3 | Public AKP keys exclude `priv` (§3). | Met | The configuration test checks exclusion; the JWKS controller test checks the complete public member set for protocol and Federation keys. |
| R4 | JWK key-material bytes use base64url (§3). | Delegated | JOSE `AKPKey` handles both `pub` and private seed encoding. OpenID helper tests cover non-canonical public encodings. `alg` remains a literal identifier, not base64url-encoded key material. |
| R5 | Private JWK `priv` is the seed, exactly 32 bytes; expanded keys are not this JWK representation (§4). | Delegated | JOSE `AKPKey::generate`, `seed` and PEM conversion enforce the seed representation and length. No module test directly tests malformed raw seeds after the test cleanup. This does not prohibit expanded private PEM representations in other specifications. |
| R6 | `pub` follows FIPS 204 §5.3; public-key and signature sizes match the parameter set (§5, table 1). | Met / delegated | Configured loading and real signing/verification cover each variant. JOSE `AKPKey::publicKey` checks public lengths; `MLDSA::verify` checks signature lengths. OpenSSL handles FIPS encoding. The module no longer independently asserts raw signature lengths. |
| R7 | Sign with FIPS 204 Algorithm 2 (§5). | Delegated | JOSE `AKPKey::sign` supplies the JWS signing input to `openssl_sign` with no digest. OpenSSL's default message encoding is pure ML-DSA. Same-stack round trips are not independent Algorithm 2 vectors. |
| R8 | ML-DSA context is empty (§5). | Delegated | No custom context is supplied by JOSE. OpenSSL documents an empty default context. No module context-discrimination vector is tested. |
| R9 | Signature bytes follow FIPS 204 §7.2 and JWS encodes them as base64url (§5). | Delegated | OpenSSL produces/consumes the signature bytes; the JOSE compact serializer/parser encodes/decodes them. Module token tests exercise serialization, parsing and verification, but do not independently validate the primitive's encoding. |
| R10 | JWK thumbprints select `alg`, `kty`, `pub`, sort lexicographically and follow RFC 7638 §3 (§6). | Met / delegated | `ModuleConfigMlDsaTest::testDerivesKeyIdFromPublicKey` and `DpopProofVerifierTest::testMlDsaProofAtTokenEndpointAndReplay` independently build canonical input, SHA-256 and unpadded base64url. Optional metadata/private members are excluded. RFC 9964 does not mandate SHA-256 for every application; these module uses choose it. |
| R11 | Existing JOSE security considerations remain applicable; consult FIPS 204 and RFC 9881 for deployment/signing guidance (§7). | Config / delegated | Existing JWS/JWK processing remains in the OpenID/JOSE dependencies. This checklist does not establish all inherited RFC 7515/7517 requirements or independently audit randomness, side channels or deterministic/randomized signing. RFC 9053 applies to the COSE branch. |
| R12 | Protect seeds as strongly as expanded private keys (§7.1; reiterated in §7.3). | Config | Deployment filesystem, secret-store, process and backup controls; unit tests cannot establish these safeguards. |
| R13 | Validate all applicable algorithm parameters before use (§7.3). | Met / delegated | JOSE `MLDSA::sign/verify` calls `AKPKey::checkKey`. Module tests reject malformed PEMs and a loaded key used with a different configured variant. OpenID helper tests cover malformed public parameters. Full primitive validation remains OpenSSL's responsibility. |
| R14 | Check seed length before use (§7.3). | Delegated | JOSE `AKPKey::seed` rejects decoded lengths other than 32 bytes. Source-inspected; no dedicated module malformed-seed test is retained. |
| R15 | FIPS public encoding/decoding inputs respect their specified ranges (§7.3). | Delegated / gap | The wrapper checks public length and imports through OpenSSL. No independent module tests exercise every `pkEncode`/`pkDecode` range condition. |
| R16 | Seed expansion uses `KeyGen_internal` and FIPS `skEncode`/`skDecode`; heed the trusted-input guidance for `skDecode` (§7.3). | Delegated / gap | JOSE loads a seed-only PKCS#8 key and asks OpenSSL to derive the public key. The module neither implements nor independently tests the internal expansion/encoding algorithms or expanded-key trust boundary. |
| R17 | HashML-DSA is not an algorithm defined here (§7.2). | Delegated | The registered names map to pure ML-DSA; no application prehash is substituted. ID-token `at_hash` is a separate token-binding hash. No HashML-DSA compatibility is claimed. |
| R18 | Account for mismatched public/private parameters (§7.4 security consideration). | Delegated / gap | JOSE `AKPKey::checkKey` compares a private JWK's `pub` with the seed-derived public key. Separately configured private/public PEM files are not compared during module configuration loading. Positive round trips do not establish rejection of mismatched files. Section 7.4 is a warning, not a separate uppercase MUST. |
| R19 | JOSE registrations: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` in `alg`; `AKP` in `kty`; `pub` public and `priv` private (§§8.1.4–8.1.6). | Met / delegated | OpenID enum, JOSE key representation, module algorithm policy and publication tests use these exact identifiers and information classes. The registry marks implementation optional; registration creates no additional runtime requirement to support every variant. |

The pure-mode/context source evidence above follows the
[OpenSSL 3.5 ML-DSA signature documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/).
Do not infer FIPS validation from use of OpenSSL or a successful round trip.

### COSE and non-implementation sections

| RFC sections | Requirement or content | Status / applicability |
|---|---|---|
| §§3–5 | COSE AKP keys have required algorithm/public parameters, exclude private material from public keys, use byte strings without JWK base64url wrapping, and share the seed, parameter-set, pure-mode/context and validation rules above. | Out of scope; this module emits JOSE, not COSE. |
| §6 | COSE AKP thumbprints select labels `1`, `3`, `-1` and follow RFC 9679 §3. | Out of scope; no COSE thumbprint implementation is claimed. |
| §§8.1.1–8.1.3 | COSE algorithm values `-48`, `-49`, `-50`, AKP key type `7`, public parameter `-1`, private parameter `-2`. | Out of scope; these are completed IANA registrations, not module implementation work. |
| §§1–2 | Scope, terminology, BCP 14 interpretation and abbreviated examples. | Interpretive; no additional implementation obligation. |
| §9, Appendix A | References and JOSE/COSE examples. | Examples are not mandatory known-answer tests; no module claim of Appendix A vector verification. |

Expected decoded lengths in bytes ([RFC 9964 §5](https://www.rfc-editor.org/rfc/rfc9964.html#section-5)):

| Variant | Public key | Signature |
|---------|------------|-----------|
| ML-DSA-44 | 1312 | 2420 |
| ML-DSA-65 | 1952 | 3309 |
| ML-DSA-87 | 2592 | 4627 |

The JWK seed remains 32 bytes for each variant. RFC table 1 also lists expanded
private keys of 2560, 4032 and 4896 bytes respectively; those are not the JWK
`priv` lengths. Signature sizes above precede JWS base64url encoding.

## Module behavior and OpenID token hashes

| # | Requirement / behavior | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 10 | Select SHAKE256, request 64 output bytes, retain the first 32, then unpadded base64url for ML-DSA `at_hash` (token hash guide §2, table 1). | Met | `IdTokenBuilder::generateAccessTokenHash`, using phpseclib `shake256-512`. | `IdTokenBuilderTest::testGeneratesMlDsaAccessTokenHash`: guide §3 vector, empty input, `abc`, and a multi-block input, for each variant. The hash is of the access-token string, not a prehash used for signing. |
| 11 | ID-token signing and `at_hash` use the selected ID-token algorithm. | Met | `IdTokenBuilder::buildFor`. | `IdTokenBuilderTest::testIssuesMlDsaIdTokenWithAccessTokenHash`; `MlDsaKeySelectionTest::testSelectsRequestedAlgorithmFromMixedConfiguredKeys` verifies real RSA/EC/ML-DSA selection, including ML-DSA ID tokens paired with RSA access tokens. Hash correctness and ID-token hash issuance are checked independently in `IdTokenBuilderTest`. |
| 12 | JWT access tokens use the configured protocol key and algorithm. | Met | `AccessTokenEntity::convertToJWT`, OpenID `JwtAccessTokenFactory`. | `AccessTokenEntityTest::testMintsMlDsaAccessTokenWithLeagueKey` signs, parses and verifies all variants while carrying the unused League key. |
| 13 | Signature verification rejects wrong keys and changed content. | Met / delegated | OpenID JWS verifier and JOSE `MLDSA`. | Library `MLDSATest` covers wrong keys and altered signatures. Module `BearerTokenValidatorTest::testMlDsaProofWithAccessTokenBinding` covers tampered DPoP signatures and valid proofs using a key different from the access-token binding. Configuration tests retain one positive signing/verification round trip. |
| 14 | Advertise supported ID-token algorithms; keep RS256 for OIDC Discovery compliance (Discovery §3). | Met / config | `OpMetadataService` intersects configured protocol algorithms with runtime support. | `OpMetadataServiceTest::testAdvertisesMlDsaOnlyForImplementedOpenIdUses`, `testOmitsUnavailableAlgorithmsFromIdTokenDiscovery`. Operators must retain an RS256 protocol key; configuration does not enforce that requirement. |
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
The token hash guide is draft 00 (4 September 2026), an implementer's guide,
not part of RFC 9964. Row 10 covers its ML-DSA digest selection, ASCII input,
left-half truncation and unpadded encoding rules (§2), including fixed XOF output
length (§4). This module change implements `at_hash`, not a general facility for
`c_hash`, `s_hash` or `rt_hash`. EdDSA parameter-set guidance and other algorithm
families are outside the new mapping and are not certified by this checklist.

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
- **External evidence:** no external ML-DSA conformance result is recorded here.
  An earlier review of `release-v5.3.1` and snapshot
  `23353b36957d6466010de767c812d2c91ed37638` found incomplete support; that is a
  historical observation, not verification of the suite's current capabilities.
  Recheck the suite before claiming current support or lack of support. Relevant
  historical sources are its
  [JWSUtil](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.1/src/main/java/net/openid/conformance/util/JWSUtil.java),
  [JWKUtil](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.1/src/main/java/net/openid/conformance/util/JWKUtil.java)
  and [JWAUtil](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.1/src/main/java/net/openid/conformance/util/JWAUtil.java).
  Existing RSA conformance runs remain protocol regression coverage.
- Crypto round trips use the same underlying implementation on both sides.
  They do not establish independent implementation interoperability or FIPS validation.

## Run the mapped module tests

From the module checkout:

```bash
vendor/bin/phpunit --no-coverage --fail-on-skipped \
  tests/unit/src/ModuleConfigMlDsaTest.php \
  tests/unit/src/Services/IdTokenBuilderTest.php \
  tests/unit/src/Services/MlDsaKeySelectionTest.php \
  tests/unit/src/Server/Grants/MlDsaGrantTest.php \
  tests/unit/src/Controllers/Federation/MlDsaEntityStatementTest.php \
  tests/unit/src/Controllers/JwksControllerTest.php \
  tests/unit/src/Entities/AccessTokenEntityTest.php \
  tests/unit/src/Services/OpMetadataServiceTest.php \
  tests/unit/src/Server/UnusedLeagueSigningKeyTest.php \
  tests/unit/src/Factories/AuthorizationServerFactoryTest.php \
  tests/unit/src/Server/Validators/DpopProofVerifierTest.php \
  tests/unit/src/Server/Validators/BearerTokenValidatorTest.php
```

Require all three enum variants (`MLDSA44`, `MLDSA65`, `MLDSA87`) to report
`isSupported()` before treating this run as positive ML-DSA evidence. The probe
checks runtime availability, while the tests exercise actual key generation,
signing and verification. PHP 8.4+ and an available OpenSSL ML-DSA provider are
required, as detailed in the installation guide. A green run made of skipped
crypto cases does not establish signing support.
