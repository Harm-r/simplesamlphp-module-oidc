<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\CoreFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\RefreshTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ScopeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Grant\RefreshTokenGrantFactory;
use SimpleSAML\Module\oidc\Factories\OAuth2Factory;
use SimpleSAML\Module\oidc\Factories\TokenResponseFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeVerifierRule;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Server\UnusedLeagueSigningKey;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\Test\Module\oidc\unit\SigningKeyTestTrait;

/**
 * Real grants, token factories and signing; repositories, rule results and logging are doubles.
 * Starts with a stored authorization code, not browser login or HTTP client authentication.
 */
#[CoversClass(AuthCodeGrant::class)]
#[CoversClass(RefreshTokenGrant::class)]
class MlDsaGrantTest extends TestCase
{
    use SigningKeyTestTrait;


    public static function algorithmProvider(): array
    {
        return [
            'ML-DSA-44' => [SignatureAlgorithmEnum::MLDSA44],
            'ML-DSA-65' => [SignatureAlgorithmEnum::MLDSA65],
            'ML-DSA-87' => [SignatureAlgorithmEnum::MLDSA87],
        ];
    }


    #[DataProvider('algorithmProvider')]
    public function testRedeemsAuthorizationCodeAndRefreshesMlDsaTokens(SignatureAlgorithmEnum $algorithm): void
    {
        $encryptionKey = Key::createNewRandomKey();
        $config = new ModuleConfig(overrides: [
            ModuleConfig::OPTION_ISSUER => 'https://op.example.org',
            ModuleConfig::OPTION_ENCRYPTION_KEY => $encryptionKey->saveToAsciiSafeString(),
            ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => [
                $this->keyEntry($algorithm, 'grant-signing-key'),
            ],
        ]);
        $logger = $this->createStub(LoggerService::class);
        $helpers = new Helpers();
        $core = (new CoreFactory($config, $logger))->build();
        $oauth2 = (new OAuth2Factory($config))->build();
        $extractor = new ClaimTranslatorExtractor(['uid'], new ClaimSetEntityFactory());
        $subjects = new SubjectResolver($extractor, $logger);
        $claims = new AccessTokenClaimsResolver($extractor, $config);
        $now = new DateTimeImmutable();
        $user = new UserEntity('user123', $now, $now, ['uid' => ['subject-at-login']]);
        $users = $this->createStub(UserRepository::class);
        $users->method('getUserEntityByIdentifier')->willReturn($user);
        $scopes = ['openid', 'profile', 'offline_access'];
        $client = new ClientEntity('client123', 'secret', 'Client', '', [], $scopes, true, true);
        $authenticated = new ResolvedClientAuthenticationMethod(
            $client,
            ClientAuthenticationMethodsEnum::ClientSecretBasic,
        );
        $code = new AuthCodeEntity(
            'code123',
            $client,
            array_map(fn(string $scope): ScopeEntity => new ScopeEntity($scope), $scopes),
            $now->add(new DateInterval('PT5M')),
            'user123',
            'https://rp.example.org/callback',
            'nonce123',
            flowTypeEnum: FlowTypeEnum::OidcAuthorizationCode,
        );
        $codes = $this->createStub(AuthCodeRepository::class);
        $codes->method('findById')->willReturn($code);
        $codes->method('consumeAuthCode')->willReturn(true);
        $accessTokens = $this->createStub(AccessTokenRepository::class);
        $refreshTokens = $this->createStub(RefreshTokenRepository::class);
        $refreshTokens->method('isRefreshTokenRevoked')->willReturn(false);
        $scopeRepository = $this->createStub(ScopeRepository::class);
        $scopeRepository->method('getScopeEntityByIdentifier')->willReturnCallback(
            fn(string $scope): ScopeEntity => new ScopeEntity($scope),
        );
        $scopeRepository->method('finalizeScopes')->willReturnArgument(0);
        $rules = $this->createStub(RequestRulesManager::class);
        $rules->method('check')->willReturnCallback(
            function (ServerRequestInterface $request, array $ruleKeys) use ($authenticated): ResultBag {
                $bag = new ResultBag();
                foreach ($ruleKeys as $ruleKey) {
                    if ($ruleKey === ClientAuthenticationRule::class) {
                        $bag->add(new Result($ruleKey, $authenticated));
                    } elseif ($ruleKey === CodeVerifierRule::class) {
                        $bag->add(new Result($ruleKey, $request->getParsedBody()['code_verifier'] ?? null));
                    }
                }
                return $bag;
            },
        );
        $params = $this->createStub(RequestParamsResolver::class);
        $params->method('getAllBasedOnAllowedMethods')->willReturnCallback(
            fn(ServerRequestInterface $request): array => (array)$request->getParsedBody(),
        );
        $params->method('getBasedOnAllowedMethods')->willReturnCallback(
            fn(string $name, ServerRequestInterface $request): mixed => $request->getParsedBody()[$name] ?? null,
        );
        $tokenFactory = new AccessTokenEntityFactory($helpers, new ScopeEntityFactory(), $oauth2, $config);
        $refreshIssuer = new RefreshTokenIssuer(
            $helpers,
            $refreshTokens,
            new RefreshTokenEntityFactory($helpers),
            $logger,
        );
        $authCodeGrant = new AuthCodeGrant(
            $codes,
            $accessTokens,
            $refreshTokens,
            new DateInterval('PT5M'),
            $rules,
            $params,
            $tokenFactory,
            new AuthCodeEntityFactory($helpers, new ScopeEntityFactory()),
            $refreshIssuer,
            $helpers,
            $logger,
            $users,
            $subjects,
            $claims,
            $config,
            $this->createStub(IssuerStateRepository::class),
        );
        $authCodeGrant->setRefreshTokenTTL($config->getRefreshTokenDuration());
        $authentication = $this->createStub(AuthenticatedOAuth2ClientResolver::class);
        $authentication->method('forAnySupportedMethod')->willReturn($authenticated);
        $refreshGrant = (new RefreshTokenGrantFactory(
            $config,
            $refreshTokens,
            $tokenFactory,
            $refreshIssuer,
            $authentication,
            $logger,
            $users,
            $subjects,
            $claims,
        ))->build();
        $leagueKey = new UnusedLeagueSigningKey();
        $responses = new TokenResponseFactory(
            $config,
            $users,
            new IdTokenBuilder($extractor, $core, $config, $subjects),
            $leagueKey,
            $logger,
        );
        $server = new AuthorizationServer(
            $this->createStub(ClientRepository::class),
            $accessTokens,
            $scopeRepository,
            $leagueKey,
            $encryptionKey,
            $responses->build(),
            $rules,
            $logger,
        );
        $server->enableGrantType($authCodeGrant, new DateInterval('PT10M'));
        $server->enableGrantType($refreshGrant, new DateInterval('PT10M'));
        $verifier = str_repeat('a', 43);
        $codePayload = [
            'auth_code_id' => 'code123', 'client_id' => 'client123', 'user_id' => 'user123',
            'redirect_uri' => 'https://rp.example.org/callback', 'scopes' => $scopes,
            'expire_time' => time() + 300, 'nonce' => 'nonce123', 'auth_time' => time() - 60,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ];
        $codeRequest = [
            'grant_type' => 'authorization_code',
            'code' => Crypto::encrypt(json_encode($codePayload, JSON_THROW_ON_ERROR), $encryptionKey),
            'redirect_uri' => 'https://rp.example.org/callback', 'code_verifier' => $verifier,
        ];
        $initial = $this->requestTokens($server, $codeRequest);
        $publicKeys = ['keys' => [$config->getProtocolSignatureKeyPairBag()->getFirstOrFail()
            ->getKeyPair()->getPublicKey()->jsonSerialize()]];
        $this->assertTokens($initial, $algorithm, $core, $oauth2, $publicKeys, $scopes);
        $initialId = $core->idTokenFactory()->fromToken($initial['id_token']);
        $this->assertSame('nonce123', $initialId->getNonce());
        $this->assertSame($codePayload['auth_time'], $initialId->getPayloadClaim('auth_time'));
        $refreshRequest = [
            'grant_type' => 'refresh_token', 'refresh_token' => $initial['refresh_token'],
            'scope' => 'openid offline_access',
        ];
        $refreshed = $this->requestTokens($server, $refreshRequest);
        $this->assertTokens($refreshed, $algorithm, $core, $oauth2, $publicKeys, ['openid', 'offline_access']);
        $this->assertNull($core->idTokenFactory()->fromToken($refreshed['id_token'])->getNonce());
        $this->assertNotSame($initial['access_token'], $refreshed['access_token']);
        $this->assertNotSame($initial['id_token'], $refreshed['id_token']);
        $this->assertNotSame($initial['refresh_token'], $refreshed['refresh_token']);
    }


    private function requestTokens(AuthorizationServer $server, array $body): array
    {
        $request = (new ServerRequest('POST', 'https://op.example.org/token'))->withParsedBody($body);
        $response = $server->respondToAccessTokenRequest($request, new Response());
        $this->assertSame(200, $response->getStatusCode());
        return json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
    }


    private function assertTokens(
        array $response,
        SignatureAlgorithmEnum $algorithm,
        Core $core,
        OAuth2 $oauth2,
        array $publicKeys,
        array $scopes,
    ): void {
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertSame(implode(' ', $scopes), $response['scope']);
        $this->assertGreaterThan(0, $response['expires_in']);
        $access = $oauth2->jwtAccessTokenFactory()->fromToken($response['access_token']);
        $id = $core->idTokenFactory()->fromToken($response['id_token']);
        foreach ([$access, $id] as $token) {
            $token->verifyWithKeySet($publicKeys);
            $this->assertSame($algorithm->value, $token->getHeaderClaim('alg'));
            $this->assertSame('grant-signing-key', $token->getKeyId());
            $this->assertSame('subject-at-login', $token->getSubject());
            $this->assertSame('https://op.example.org', $token->getIssuer());
            $this->assertSame(['client123'], $token->getAudience());
        }
        $this->assertSame('at+jwt', $access->getType());
        $this->assertSame($scopes, $access->getScopes());
    }
}
