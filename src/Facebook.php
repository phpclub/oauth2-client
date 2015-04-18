<?php

namespace OAuth2;

class Facebook extends AbstractProvider
{
    /**
     * @const string The fallback Graph API version to use for requests.
     */
    const DEFAULT_GRAPH_VERSION = 'v2.2';

    /**
     * @var string The Graph API version to use for requests.
     */
    protected $graphApiVersion;

    public $scopes = ['public_profile', 'email'];

    public $responseType = 'string';

    public function __construct($options)
    {
        parent::__construct($options);
        $this->graphApiVersion = (isset($options['graphApiVersion']))
            ? $options['graphApiVersion']
            : static::DEFAULT_GRAPH_VERSION;
    }

    public function urlAuthorize()
    {
        return 'https://www.facebook.com/'.$this->graphApiVersion.'/dialog/oauth';
    }

    public function urlAccessToken()
    {
        return 'https://graph.facebook.com/'.$this->graphApiVersion.'/oauth/access_token';
    }

    public function urlUserDetails(AccessToken $token)
    {
        $fields = implode(',', [
            'id',
            'name',
            'first_name',
            'last_name',
            'email',
            'hometown',
            'bio',
            'picture.type(large){url}',
            'gender',
            'locale',
            'link',
        ]);

        return 'https://graph.facebook.com/'.$this->graphApiVersion.'/me?fields='.$fields.'&access_token='.$token;
    }

    public function userDetails($response, AccessToken $token)
    {
        $email = (isset($response->email)) ? $response->email : null;
        // The "hometown" field will only be returned if you ask for the `user_hometown` permission.
        $location = (isset($response->hometown->name)) ? $response->hometown->name : null;
        $description = (isset($response->bio)) ? $response->bio : null;
        $imageUrl = (isset($response->picture->data->url)) ? $response->picture->data->url : null;
        $gender = (isset($response->gender)) ? $response->gender : null;
        $locale = (isset($response->locale)) ? $response->locale : null;

        return [
            'uid' => $response->id,
            'name' => $response->name,
            'firstname' => $response->first_name,
            'lastname' => $response->last_name,
            'email' => $email,
            'location' => $location,
            'description' => $description,
            'image_url' => $imageUrl,
            'gender' => $gender,
            'locale' => $locale,
            'urls' => [ 'Facebook' => $response->link ],
        ];
    }
}
