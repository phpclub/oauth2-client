<?php

namespace OAuth2\Test;

class GoogleTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Google([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
            'hostedDomain' => 'mock_domain',
            'accessType' => 'mock_access_type'
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
        $this->assertArrayHasKey('hd', $query);
        $this->assertArrayHasKey('access_type', $query);
        $this->assertNotNull($this->provider->state);
    }

    public function testUrlAccessToken()
    {
        $url = $this->provider->urlAccessToken();
        $uri = parse_url($url);

        $this->assertEquals('/o/oauth2/token', $uri['path']);
    }

    public function testGetAccessToken()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->accessToken);
        $this->assertLessThanOrEqual(time() + 3600, $token->expires);
        $this->assertGreaterThanOrEqual(time(), $token->expires);
        $this->assertEquals('mock_refresh_token', $token->refreshToken);
        $this->assertEquals('1', $token->uid);
    }

    public function testScopes()
    {
        $this->assertEquals(['profile', 'email'], $this->provider->getScopes());
    }

    public function testUserData()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"emails": [{"value": "mock_email"}],"id": "12345","displayName": "mock_name","name": {"familyName": "mock_last_name","givenName": "mock_first_name"},"image": {"url": "mock_image_url"}}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getUserDetails($token);

        $this->assertEquals(12345, $user['uid']);
        $this->assertEquals('mock_first_name', $user['firstname']);
        $this->assertEquals('mock_last_name', $user['lastname']);
        $this->assertEquals('mock_email', $user['email']);
    }

    public function testGetHostedDomain()
    {
        $this->assertEquals('mock_domain', $this->provider->getHostedDomain());
    }

    public function testSetHostedDomain()
    {
        $this->provider->setHostedDomain('changed_domain');
        $this->assertEquals('changed_domain', $this->provider->hostedDomain);
    }

    public function testGetAccessType()
    {
        $this->assertEquals('mock_access_type', $this->provider->getAccessType());
    }

    public function testSetAccessType()
    {
        $this->provider->setAccessType('changed_access_type');
        $this->assertEquals('changed_access_type', $this->provider->accessType);
    }
}
