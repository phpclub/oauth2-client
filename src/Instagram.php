<?php

namespace OAuth2;

class Instagram extends AbstractProvider
{
    public $scopes = ['basic'];
    public $responseType = 'json';

    public function urlAuthorize()
    {
        return 'https://api.instagram.com/oauth/authorize';
    }

    public function urlAccessToken()
    {
        return 'https://api.instagram.com/oauth/access_token';
    }

    public function urlUserDetails(AccessToken $token)
    {
        return 'https://api.instagram.com/v1/users/self?access_token='.$token;
    }

    public function userDetails($response, AccessToken $token)
    {
        $description = (isset($response->data->bio)) ? $response->data->bio : null;
        return [
            'uid' => $response->data->id,
            'nickname' => $response->data->username,
            'name' => $response->data->full_name,
            'description' => $description,
            'image_url' => $response->data->profile_picture,
        ];
    }
}
