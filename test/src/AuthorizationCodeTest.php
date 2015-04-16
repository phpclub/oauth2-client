<?php

namespace OAuth2\Test;

class AuthorizationCodeTest extends \PHPUnit_Framework_TestCase
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

    /**
     * @expectedException BadMethodCallException
     */
    public function testInvalidRefreshToken()
    {
        $this->provider->getAccessToken('authorization_code', ['invalid_code' => 'mock_authorization_code']);
    }
}
