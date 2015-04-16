<?php

namespace OAuth2\Test;

class FacebookTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Facebook([
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
        $graphVersion = \OAuth2\Facebook::DEFAULT_GRAPH_VERSION;

        $this->assertEquals('/'.$graphVersion.'/oauth/access_token', $uri['path']);
    }

    public function testGraphApiVersionCanBeCustomized()
    {
        $graphVersion = 'v13.37';
        $provider = new \OAuth2\Facebook([
            'graphApiVersion' => $graphVersion,
        ]);
        $fooToken = new \OAuth2\AccessToken(['access_token' => 'foo_token']);

        $urlAuthorize = $provider->urlAuthorize();
        $urlAccessToken = $provider->urlAccessToken();
        $urlUserDetails = parse_url($provider->urlUserDetails($fooToken), PHP_URL_PATH);

        $this->assertEquals('https://www.facebook.com/'.$graphVersion.'/dialog/oauth', $urlAuthorize);
        $this->assertEquals('https://graph.facebook.com/'.$graphVersion.'/oauth/access_token', $urlAccessToken);
        $this->assertEquals('/'.$graphVersion.'/me', $urlUserDetails);
    }

    public function testGraphApiVersionWillFallbackToDefault()
    {
        $graphVersion = \OAuth2\Facebook::DEFAULT_GRAPH_VERSION;
        $fooToken = new \OAuth2\AccessToken(['access_token' => 'foo_token']);

        $urlAuthorize = $this->provider->urlAuthorize();
        $urlAccessToken = $this->provider->urlAccessToken();
        $urlUserDetails = parse_url($this->provider->urlUserDetails($fooToken), PHP_URL_PATH);

        $this->assertEquals('https://www.facebook.com/'.$graphVersion.'/dialog/oauth', $urlAuthorize);
        $this->assertEquals('https://graph.facebook.com/'.$graphVersion.'/oauth/access_token', $urlAccessToken);
        $this->assertEquals('/'.$graphVersion.'/me', $urlUserDetails);
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

    public function testScopes()
    {
        $this->assertEquals(['public_profile', 'email'], $this->provider->getScopes());
    }

    public function testUserData()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', 'access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&uid=1');
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"id": 12345, "name": "mock_name", "username": "mock_username", "first_name": "mock_first_name", "last_name": "mock_last_name", "email": "mock_email", "Location": "mock_home", "bio": "mock_description", "link": "mock_facebook_url", "picture": {"data":{"url":"mock_image_url"}}}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getUserDetails($token);

        $this->assertEquals(12345, $user['uid']);
        $this->assertEquals('mock_first_name', $user['firstname']);
        $this->assertEquals('mock_last_name', $user['lastname']);
        $this->assertEquals('mock_email', $user['email']);
        $this->assertEquals('mock_image_url', $user['image_url']);
    }
}
