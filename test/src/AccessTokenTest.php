<?php

namespace OAuth2\Test;

class AccessTokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException InvalidArgumentException
     */
    public function testInvalidRefreshToken()
    {
        new \OAuth2\AccessToken(['invalid_access_token' => 'none']);
    }

    public function testExpiresInCorrection()
    {
        $options = array('access_token' => 'access_token', 'expires_in' => 100);
        $token = new \OAuth2\AccessToken($options);
        $this->assertNotNull($token->expires);
    }
}
