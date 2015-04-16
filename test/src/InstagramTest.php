<?php

namespace OAuth2\Test;

class InstagramTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Instagram([
            'clientId' => 'mock_client_id',
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

        $this->assertEquals('/oauth/access_token', $uri['path']);
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
        $this->assertEquals(['basic'], $this->provider->getScopes());
    }

    public function testUserData()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"data": {"id": "12345", "username": "mock_username", "full_name": "mock_full_name", "bio": "mock_bio", "profile_picture": "mock_profile_picture"}}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getUserDetails($token);

        $this->assertEquals(12345, $user['uid']);
        $this->assertEquals('mock_full_name', $user['name']);
        $this->assertEquals(true, !isset($user['email']));
    }
}
