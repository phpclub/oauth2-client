<?php

namespace OAuth2\Test;

class GithubTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Github([
            'clientId' => 'mock',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ]);
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->state);
    }

    public function testUrlAccessToken()
    {
        $url = $this->provider->urlAccessToken();
        $uri = parse_url($url);

        $this->assertEquals('/login/oauth/access_token', $uri['path']);
    }

    public function testGetAccessToken()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&uid=1');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->accessToken);
        $this->assertLessThanOrEqual(time() + 3600, $token->expires);
        $this->assertGreaterThanOrEqual(time(), $token->expires);
        $this->assertEquals('mock_refresh_token', $token->refreshToken);
        $this->assertEquals('1', $token->uid);
    }

    /**
     * @ticket 230
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Required option not passed: access_token
     */
    public function testGetAccessTokenWithInvalidJson()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'invalid');

        $this->provider->responseType = 'json';

        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    public function testGetAccessTokenSetResultUid()
    {
        $this->provider->uidKey = 'otherKey';

        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->accessToken);
        $this->assertLessThanOrEqual(time() + 3600, $token->expires);
        $this->assertGreaterThanOrEqual(time(), $token->expires);
        $this->assertEquals('mock_refresh_token', $token->refreshToken);
        $this->assertEquals('{1234}', $token->uid);
    }

    public function testScopes()
    {
        $this->provider->setScopes(['user', 'repo']);
        $this->assertEquals(['user', 'repo'], $this->provider->getScopes());
    }

    public function testUserData()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&uid=1');
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"id": 12345, "login": "mock_login", "name": "mock_name", "email": "mock_email"}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getUserDetails($token);

        $this->assertEquals(12345, $user['uid']);
        $this->assertEquals('mock_name', $user['name']);
        $this->assertEquals('mock_email', $user['email']);
    }

    public function testGithubDomainUrls()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals($this->provider->domain.'/login/oauth/authorize', $this->provider->urlAuthorize());
        $this->assertEquals($this->provider->domain.'/login/oauth/access_token', $this->provider->urlAccessToken());
        $this->assertEquals($this->provider->apiDomain.'/user', $this->provider->urlUserDetails($token));
        $this->assertEquals($this->provider->apiDomain.'/user/emails', $this->provider->urlUserEmails($token));
    }

    public function testGithubEnterpriseDomainUrls()
    {
        $this->provider->domain = 'https://github.company.com';

        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals($this->provider->domain.'/login/oauth/authorize', $this->provider->urlAuthorize());
        $this->assertEquals($this->provider->domain.'/login/oauth/access_token', $this->provider->urlAccessToken());
        $this->assertEquals($this->provider->domain.'/api/v3/user', $this->provider->urlUserDetails($token));
        $this->assertEquals($this->provider->domain.'/api/v3/user/emails', $this->provider->urlUserEmails($token));
    }

    public function testUserEmails()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&uid=1');
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '[{"email":"mock_email_1","primary":false,"verified":true},{"email":"mock_email_2","primary":false,"verified":true},{"email":"mock_email_3","primary":true,"verified":true}]');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $emails = $this->provider->getUserEmails($token);

        $this->assertInternalType('array', $emails);
        $this->assertCount(3, $emails);
        $this->assertEquals('mock_email_3', $emails[2]->email);
        $this->assertTrue($emails[2]->primary);
    }
}
