<?php

namespace OAuth2\Test;

class AbstractProviderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var AbstractProvider
     */
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \OAuth2\Google([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ]);
    }

    public function testAuthorizationUrlStateParam()
    {
        $this->assertContains('state=XXX', $this->provider->getAuthorizationUrl([
            'state' => 'XXX'
        ]));
    }

    /**
     * Tests https://github.com/thephpleague/oauth2-client/issues/134
     */
    public function testConstructorSetsProperties()
    {
        $options = [
            'clientId' => '1234',
            'clientSecret' => '4567',
            'redirectUri' => 'http://example.org/redirect',
            'state' => 'foo',
            'name' => 'bar',
            'uidKey' => 'mynewuid',
            'scopes' => ['a', 'b', 'c'],
            'method' => 'get',
            'scopeSeparator' => ';',
            'responseType' => 'csv',
            'headers' => ['Foo' => 'Bar'],
            'authorizationHeader' => 'Bearer',
        ];

        $mockProvider = new MockProvider($options);

        foreach ($options as $key => $value)
        {
            $this->assertEquals($value, $mockProvider->{$key});
        }
    }

    public function testSetRedirectHandler()
    {
        $this->testFunction = false;

        $callback = function ($url) {
            $this->testFunction = $url;
        };

        $this->provider->setRedirectHandler($callback);

        $this->provider->authorize('http://test.url/');

        $this->assertNotFalse($this->testFunction);
    }

    public function getHeadersTest()
    {
        $provider = $this->getMockForAbstractClass(
            '\OAuth2\AbstractProvider',
            [
                [
                    'clientId'     => 'mock_client_id',
                    'clientSecret' => 'mock_secret',
                    'redirectUri'  => 'none',
                ]
            ]
        );

        /**
         * @var $provider AbstractProvider
         */
        $this->assertEquals([], $provider->getHeaders());
        $this->assertEquals([], $provider->getHeaders('mock_token'));

        $provider->authorizationHeader = 'Bearer';
        $this->assertEquals(['Authorization: Bearer abc'], $provider->getHeaders('abc'));

        $token = new \OAuth2\AccessToken(['access_token' => 'xyz', 'expires_in' => 3600]);
        $this->assertEquals(['Authorization: Bearer xyz'], $provider->getHeaders($token));
    }
}

class MockProvider extends \OAuth2\AbstractProvider
{
    public function urlAuthorize()
    {
        return '';
    }

    public function urlAccessToken()
    {
        return '';
    }

    public function urlUserDetails(\OAuth2\AccessToken $token)
    {
        return '';
    }

    public function userDetails($response, \OAuth2\AccessToken $token)
    {
        return '';
    }
}
