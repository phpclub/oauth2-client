<?php

namespace OAuth2\Test;

class VkontakteTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Vkontakte([
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

        $this->assertEquals('/access_token', $uri['path']);
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
        $this->assertEquals([], $this->provider->getScopes());
    }

    public function testUserData()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"response": [{"uid": 12345, "nickname": "mock_nickname", "screen_name": "mock_name", "first_name": "mock_first_name", "last_name": "mock_last_name", "email": "mock_email", "country": "UK", "status": "mock_status", "photo_200_orig": "mock_image_url"}]}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getUserDetails($token);

        $this->assertEquals(12345, $user['uid']);
        $this->assertEquals('mock_first_name', $user['firstname']);
        $this->assertEquals('mock_last_name', $user['lastname']);
        $this->assertEquals('mock_email', $user['email']);
        $this->assertEquals('mock_image_url', $user['image_url']);
    }
}
