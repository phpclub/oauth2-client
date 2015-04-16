<?php

namespace OAuth2;

class Github extends AbstractProvider
{
    public $responseType = 'string';

    public $authorizationHeader = 'token';

    public $domain = 'https://github.com';

    public $apiDomain = 'https://api.github.com';

    public function urlAuthorize()
    {
        return $this->domain.'/login/oauth/authorize';
    }

    public function urlAccessToken()
    {
        return $this->domain.'/login/oauth/access_token';
    }

    public function urlUserDetails(AccessToken $token)
    {
        if ($this->domain === 'https://github.com')
        {
            return $this->apiDomain.'/user';
        }
        return $this->domain.'/api/v3/user';
    }

    public function urlUserEmails(AccessToken $token)
    {
        if ($this->domain === 'https://github.com')
        {
            return $this->apiDomain.'/user/emails';
        }
        return $this->domain.'/api/v3/user/emails';
    }

    public function userDetails($response, AccessToken $token)
    {
        $name = (isset($response->name)) ? $response->name : null;
        $email = (isset($response->email)) ? $response->email : null;

        return [
            'uid' => $response->id,
            'nickname' => $response->login,
            'name' => $name,
            'email' => $email,
            'urls'  => [
                'GitHub' => $this->domain.'/'.$response->login,
            ],
        ];
    }

    public function getUserEmails(AccessToken $token)
    {
        $response = $this->fetchUserEmails($token);
        return json_decode($response);
    }

    protected function fetchUserEmails(AccessToken $token)
    {
        $url = $this->urlUserEmails($token);

        $headers = $this->getHeaders($token);

        return $this->fetchProviderData($url, $headers);
    }
}
