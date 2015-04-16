<?php

namespace OAuth2;

class LinkedIn extends AbstractProvider
{
    public $scopes = ['r_basicprofile r_emailaddress r_contactinfo'];
    public $responseType = 'json';
    public $authorizationHeader = 'Bearer';
    public $fields = [
        'id', 'email-address', 'first-name', 'last-name', 'headline',
        'location', 'industry', 'picture-url', 'public-profile-url',
    ];

    public function urlAuthorize()
    {
        return 'https://www.linkedin.com/uas/oauth2/authorization';
    }

    public function urlAccessToken()
    {
        return 'https://www.linkedin.com/uas/oauth2/accessToken';
    }

    public function urlUserDetails(AccessToken $token)
    {
        $fields = implode(',', $this->fields);
        return 'https://api.linkedin.com/v1/people/~:(' . $fields . ')?format=json';
    }

    public function userDetails($response, AccessToken $token)
    {
        $email = (isset($response->emailAddress)) ? $response->emailAddress : null;
        $location = (isset($response->location->name)) ? $response->location->name : null;
        $description = (isset($response->headline)) ? $response->headline : null;
        $pictureUrl = (isset($response->pictureUrl)) ? $response->pictureUrl : null;

        return [
            'uid' => $response->id,
            'name' => $response->firstName.' '.$response->lastName,
            'firstname' => $response->firstName,
            'lastname' => $response->lastName,
            'email' => $email,
            'location' => $location,
            'description' => $description,
            'image_url' => $pictureUrl,
            'urls' => $response->publicProfileUrl,
        ];
    }
}
