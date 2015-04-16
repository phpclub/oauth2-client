<?php

namespace OAuth2\Test;

class PasswordTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Google(array(
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ));
    }

    public function testGetAccessToken()
    {
        \OAuth2\CurlMock::addPendingResponse(true, "200 OK", '', '{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');

        $token = $this->provider->getAccessToken('password', array('username' => 'mock_username', 'password' => 'mock_password'));
        $this->assertInstanceOf('\OAuth2\AccessToken', $token);
    }

    /**
     * @expectedException BadMethodCallException
     */
    public function testInvalidUsername()
    {
        $this->provider->getAccessToken('password', array('invalid_username' => 'mock_username', 'password' => 'mock_password'));
    }

    /**
     * @expectedException BadMethodCallException
     */
    public function testInvalidPassword()
    {
        $this->provider->getAccessToken('password', array('username' => 'mock_username', 'invalid_password' => 'mock_password'));
    }
}
