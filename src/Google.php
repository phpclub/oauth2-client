<?php

namespace OAuth2;

class Google extends AbstractProvider
{
    public $scopeSeparator = ' ';

    public $scopes = [
        'profile',
        'email',
    ];

    public $authorizationHeader = 'OAuth';

    /**
     * @var string If set, this will be sent to google as the "hd" parameter.
     * @link https://developers.google.com/accounts/docs/OAuth2Login#hd-param
     */
    public $hostedDomain = '';

    public function setHostedDomain($hd)
    {
        $this->hostedDomain = $hd;
    }

    public function getHostedDomain()
    {
        return $this->hostedDomain;
    }

    /**
     * @var string If set, this will be sent to google as the "access_type" parameter.
     * @link https://developers.google.com/accounts/docs/OAuth2WebServer#offline
     */
    public $accessType = '';

    public function setAccessType($accessType)
    {
        $this->accessType = $accessType;
    }

    public function getAccessType()
    {
        return $this->accessType;
    }

    public function urlAuthorize()
    {
        return 'https://accounts.google.com/o/oauth2/auth';
    }

    public function urlAccessToken()
    {
        return 'https://accounts.google.com/o/oauth2/token';
    }

    public function urlUserDetails(AccessToken $token)
    {
        return
            'https://www.googleapis.com/plus/v1/people/me?'.
            'fields=id%2Cname(familyName%2CgivenName)%2CdisplayName%2C'.
            'emails%2Fvalue%2Cimage%2Furl&alt=json';
    }

    public function userDetails($response, AccessToken $token)
    {
        $response = (array) $response;

        $imageUrl = (isset($response['image']) &&
            $response['image']->url) ? $response['image']->url : null;
        $email = (isset($response['emails']) && count($response['emails']) &&
            $response['emails'][0]->value) ? $response['emails'][0]->value : null;

        return [
            'uid' => $response['id'],
            'name' => $response['displayName'],
            'firstname' => $response['name']->givenName,
            'lastname' => $response['name']->familyName,
            'email' => $email,
            'image_url' => $imageUrl,
        ];
    }

    public function getAuthorizationUrl($options = array())
    {
        $url = parent::getAuthorizationUrl($options);

        if (!empty($this->hostedDomain))
        {
            $url .= '&' . http_build_query(['hd' => $this->hostedDomain]);
        }

        if (!empty($this->accessType))
        {
            $url .= '&' . http_build_query(['access_type'=> $this->accessType]);
        }

        return $url;
    }
}
