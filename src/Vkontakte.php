<?php

namespace OAuth2;

class Vkontakte extends AbstractProvider
{
    public $uidKey = 'user_id';

    public function urlAuthorize()
    {
        return 'https://oauth.vk.com/authorize';
    }

    public function urlAccessToken()
    {
        return 'https://oauth.vk.com/access_token';
    }

    public function urlUserDetails(AccessToken $token)
    {
        $fields = [
            'nickname',
            'screen_name',
            'sex',
            'bdate',
            'city',
            'country',
            'timezone',
            'photo_50',
            'photo_100',
            'photo_200_orig',
            'has_mobile',
            'contacts',
            'education',
            'online',
            'counters',
            'relation',
            'last_seen',
            'status',
            'can_write_private_message',
            'can_see_all_posts',
            'can_see_audio',
            'can_post',
            'universities',
            'schools',
            'verified'
        ];

        return "https://api.vk.com/method/users.get?user_id={$token->uid}&fields="
            .implode(",", $fields)."&access_token={$token}";
    }

    public function userDetails($response, AccessToken $token)
    {
        $response = $response->response[0];

        $email = (isset($response->email)) ? $response->email : null;
        $location = (isset($response->country)) ? $response->country : null;
        $description = (isset($response->status)) ? $response->status : null;

        return [
            'uid' => $response->uid,
            'nickname' => $response->nickname,
            'name' => $response->screen_name,
            'firstname' => $response->first_name,
            'lastname' => $response->last_name,
            'email' => $email,
            'location' => $location,
            'description' => $description,
            'image_url' => $response->photo_200_orig,
        ];
    }
}
