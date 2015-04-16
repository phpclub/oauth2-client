<?php

namespace OAuth2\Test;

class RefreshTokenTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Google([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ]);
    }

    public function testGetAccessToken()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $this->assertInstanceOf('OAuth2\AccessToken', $token);

        $newToken = $this->provider->getAccessToken('refresh_token', ['refresh_token' => $token->refreshToken]);
        $this->assertInstanceOf('OAuth2\AccessToken', $newToken);
    }

    /**
     * @expectedException BadMethodCallException
     */
    public function testInvalidRefreshToken()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $refreshToken = $this->provider->getAccessToken('refresh_token', ['invalid_refresh_token' => $token->refreshToken]);
    }
}
