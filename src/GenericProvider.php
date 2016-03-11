<?php

namespace OAuth2;

class GenericProvider extends AbstractProvider
{
    public $scopes = ['basic'];
    public $responseType = 'json';
    public $urlAuthorize, $urlAccessToken, $urlUserDetails;
    public $authorizationHeader = 'Bearer';

    public function urlAuthorize()
    {
        return $this->urlAuthorize;
    }

    public function urlAccessToken()
    {
        return $this->urlAccessToken;
    }

    public function urlUserDetails(AccessToken $token)
    {
        return str_replace('$token', $token, $this->urlUserDetails);
    }

    public function userDetails($response, AccessToken $token)
    {
        return $response;
    }
}
