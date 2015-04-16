<?php

namespace OAuth2;

class Microsoft extends AbstractProvider
{
    public $scopes = ['wl.basic', 'wl.emails'];
    public $responseType = 'json';

    public function urlAuthorize()
    {
        return 'https://login.live.com/oauth20_authorize.srf';
    }

    public function urlAccessToken()
    {
        return 'https://login.live.com/oauth20_token.srf';
    }

    public function urlUserDetails(AccessToken $token)
    {
        return 'https://apis.live.net/v5.0/me?access_token='.$token;
    }

    public function userDetails($response, AccessToken $token)
    {
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => 'https://apis.live.net/v5.0/'.$response->id.'/picture',
            CURLOPT_FOLLOWLOCATION => 0,
            CURLOPT_HEADER => 1,
            CURLOPT_RETURNTRANSFER => 1,
        ]);
        $redir = curl_exec($curl);
        curl_close($curl);
        preg_match('/^Location: (.*)$/im', $redir, $m);
        $imageUrl = $m ? $m[1] : false;

        $email = (isset($response->emails->preferred)) ? $response->emails->preferred : null;

        return [
            'uid' => $response->id,
            'name' => $response->name,
            'firstname' => $response->first_name,
            'lastname' => $response->last_name,
            'email' => $email,
            'image_url' => $imageUrl,
            'urls' => $response->link.'/cid-'.$response->id,
        ];
    }
}
