<?php

namespace OAuth2;

class OAuth1Provider extends AbstractProvider
{
    public $siteUrl = '';
    public $authorizeUrl = '';
    public $requestTokenUrl = '';
    public $accessTokenUrl = '';

    public $callbackUrl = '';
    public $consumerKey = '';
    public $consumerSecret = '';

    public $clientId = '';
    public $clientSecret = '';
    public $redirectUri = '';

    public $state;
    public $name;
    public $uidKey = 'uid';
    public $method = 'post';
    public $responseType = 'string';
    public $headers = [];
    public $authorizationHeader;

    protected $redirectHandler;

    public function __construct($options = [])
    {
        foreach ($options as $option => $value)
        {
            if (property_exists($this, $option))
            {
                $this->{$option} = $value;
            }
        }
    }

    /**
     * Get the URL that this provider users to request an unauthenticated "request token"
     * which may then be exchanged for an access token.
     *
     * This URL MUST be in normalized form (lowercase, no query parameters, port excluded
     * ONLY if equal to standard http 80 or https 443).
     *
     * @return string
     */
    abstract public function urlRequestToken();

    protected function nonce()
    {
        $max = 1+mt_getrandmax();
        $bits = 0;
        while ($max)
        {
            $max = $max >> 1;
            $bits++;
        }
        $r = '';
        for ($i = 0; $i < 256; $i += $bits)
        {
            $r .= pack('L', mt_rand());
        }
    }

    protected function sign($post, $url, &$params, $token = NULL)
    {
        $params = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_nonce' => base64_encode(pack('LLLL', mt_rand(), mt_rand(), mt_rand(), mt_rand())),
        ] + $params;
        ksort($params);
        $baseStr = ($post ? 'POST' : 'GET').'&'.rawurlencode($url).
            '&'.rawurlencode(http_build_query($params, '', '&', PHP_QUERY_RFC3986));
        $key = rawurlencode($this->consumerSecret).'&'.($token ? rawurlencode($token->tokenSecret) : ''));
        $params['oauth_signature'] = hash_hmac('sha1', $baseStr, $key, true);
    }

    protected function request($url, $params, $token)
    {
        $this->sign($this->method == 'POST', $url, $params, $token);
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            // No providers included with this library use GET but 3rd parties may
            CURLOPT_POST => $this->method == 'POST',
            CURLOPT_HTTPHEADER => $this->getHeaders($params),
            CURLOPT_HEADER => true,
            CURLOPT_RETURNTRANSFER => true,
        ]);
        $response = curl_exec($curl);
        curl_close($curl);
        $response = explode("\r\n\r\n", $response, 2);
        $header = explode("\r\n", $response[0]);
        $status = explode(" ", $header[0], 3);
        if ($status[1] != 200)
        {
            throw new \Exception($header[0]);
        }
        $response = $response[1];
        switch ($this->responseType)
        {
            case 'json':
                $result = json_decode($response, true);
                if (JSON_ERROR_NONE !== json_last_error())
                {
                    $result = [];
                }
                break;
            case 'string':
                $result = [];
                parse_str($response, $result);
                break;
        }
        return $result;
    }

    public function getAuthorizationUrl($options = [])
    {
        $result = $this->request($this->urlRequestToken(), []);
        $this->state = [ 'request_token' => $result ];
        $params = [
            'oauth_callback' => $this->redirectUri,
            'oauth_token' => $this->state['request_token']['oauth_token'],
        ];
        return $this->urlAuthorize().'?'.http_build_query($params);
    }

    public function authorize($options = [])
    {
        $url = $this->getAuthorizationUrl($options);
        if ($this->redirectHandler)
        {
            $handler = $this->redirectHandler;
            return $handler($url);
        }
        header('Location: ' . $url);
        exit;
    }

    public function getAccessToken($grant = 'authorization_code', $params = [])
    {
        $result = $this->request($this->urlAccessToken(), [
            'oauth_token' => $this->state['request_token'],
        ]);
        $result = $this->prepareAccessTokenResult($result);
        return new AccessToken($result);
    }

    public function getUserDetails(AccessToken $token)
    {
        $response = $this->fetchUserDetails($token);

        return $this->userDetails(json_decode($response), $token);
    }

    protected function fetchUserDetails(AccessToken $token)
    {
        $url = $this->urlUserDetails($token);

        $headers = $this->getHeaders($token);

        return $this->fetchProviderData($url, $headers);
    }

    protected function fetchProviderData($url, array $headers = [])
    {
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
        ]);
        $response = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        if ($status != 200)
        {
            throw new \Exception($response);
        }
        return $response;
    }

    public function getAuthorizationHeaders($params)
    {
        foreach ($params as $k => &$v)
        {
            $v = $k.'="'.rawurlencode($v).'"';
        }
        return [ 'Authorization: OAuth '.implode(', ', $params) ];
    }
}
