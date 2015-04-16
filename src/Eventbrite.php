<?php

namespace OAuth2;

class Eventbrite extends AbstractProvider
{
    public $authorizationHeader = 'Bearer';

    public function urlAuthorize()
    {
        return 'https://www.eventbrite.com/oauth/authorize';
    }

    public function urlAccessToken()
    {
        return 'https://www.eventbrite.com/oauth/token';
    }

    public function urlUserDetails(AccessToken $token)
    {
        return 'https://www.eventbrite.com/json/user_get';
    }

    public function userDetails($response, AccessToken $token)
    {
        return [
            'uid' => $response->user->user_id,
            'email' => $response->user->email,
        ];
    }
}
