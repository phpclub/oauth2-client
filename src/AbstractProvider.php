<?php

namespace OAuth2;

interface ProviderInterface
{
    public function urlAuthorize();

    public function urlAccessToken();

    public function urlUserDetails(AccessToken $token);

    public function userDetails($response, AccessToken $token);

    public function getScopes();

    public function setScopes(array $scopes);

    public function getAuthorizationUrl($options = []);

    public function authorize($options = []);

    public function getAccessToken($grant = 'authorization_code', $params = []);

    public function getHeaders($token = null);

    public function getUserDetails(AccessToken $token);
}

abstract class AbstractProvider implements ProviderInterface
{
    public $clientId = '';
    public $clientSecret = '';
    public $redirectUri = '';
    public $state;
    public $name;
    public $uidKey = 'uid';
    public $scopes = [];
    public $method = 'post';
    public $scopeSeparator = ',';
    public $responseType = 'json';
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
     * Get the URL that this provider uses to begin authorization.
     *
     * @return string
     */
    abstract public function urlAuthorize();

    /**
     * Get the URL that this provider users to request an access token.
     *
     * @return string
     */
    abstract public function urlAccessToken();

    /**
     * Get the URL that this provider uses to request user details.
     *
     * Since this URL is typically an authorized route, most providers will require you to pass the access_token as
     * a parameter to the request. For example, the google url is:
     *
     * 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token='.$token
     *
     * @param AccessToken $token
     * @return string
     */
    abstract public function urlUserDetails(AccessToken $token);

    /**
     * Given an object response from the server, process the user details into a format expected by the user
     * of the client.
     *
     * @param object $response
     * @param AccessToken $token
     * @return mixed
     */
    abstract public function userDetails($response, AccessToken $token);

    public function getScopes()
    {
        return $this->scopes;
    }

    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
    }

    public function getAuthorizationUrl($options = [])
    {
        $this->state = isset($options['state']) ? $options['state'] : md5(uniqid(rand(), true));

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $this->state,
            'scope' => is_array($this->scopes) ? implode($this->scopeSeparator, $this->scopes) : $this->scopes,
            'response_type' => isset($options['response_type']) ? $options['response_type'] : 'code',
            'approval_prompt' => isset($options['approval_prompt']) ? $options['approval_prompt'] : 'auto',
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

    /**
     * @param string $grant: grant type, one of 'authorization_code' (default), 'client_credentials', 'refresh_token', 'password'
     */
    public function getAccessToken($grant = 'authorization_code', $params = [])
    {
        if ($grant == 'password' && (empty($params['username']) || empty($params['password'])))
        {
            throw new \BadMethodCallException('Missing username or password');
        }
        elseif ($grant == 'authorization_code' && empty($params['code']))
        {
            throw new \BadMethodCallException('Missing authorization code');
        }
        elseif ($grant == 'refresh_token' && empty($params['refresh_token']))
        {
            throw new \BadMethodCallException('Missing refresh_token');
        }

        $requestParams = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'grant_type'    => $grant,
        ] + $params;

        $curl = curl_init();
        if (strtoupper($this->method) == 'POST')
        {
            curl_setopt_array($curl, [
                CURLOPT_URL => ($url = $this->urlAccessToken()),
                CURLOPT_POST => 1,
                CURLOPT_HTTPHEADER => $this->getHeaders(),
                CURLOPT_POSTFIELDS => http_build_query($requestParams),
                CURLOPT_RETURNTRANSFER => true,
            ]);
        }
        else
        {
            // No providers included with this library use get but 3rd parties may
            curl_setopt_array($curl, [
                CURLOPT_URL => ($url = $this->urlAccessToken() . '?' . http_build_query($requestParams)),
                CURLOPT_HTTPHEADER => $this->getHeaders(),
                CURLOPT_RETURNTRANSFER => true,
            ]);
        }
        $response = curl_exec($curl);
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $errno = curl_errno($curl);
        $error = curl_error($curl);
        curl_close($curl);

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

        if (isset($result['error']) && !empty($result['error']))
        {
            // OAuth 2.0 Draft 10 style
            throw new \Exception($result['error']);
        }
        elseif (!$result)
        {
            // cURL?
            throw new \Exception($url . ' returned: ' . ($code ? "HTTP $code, content: $response" : "cURL: $errno $error"));
        }

        $result = $this->prepareAccessTokenResult($result);

        return new AccessToken($result);
    }

    /**
     * Prepare the access token response for the grant. Custom mapping of
     * expirations, etc should be done here.
     *
     * @param  array $result
     * @return array
     */
    protected function prepareAccessTokenResult(array $result)
    {
        $this->setResultUid($result);
        return $result;
    }

    /**
     * Sets any result keys we've received matching our provider-defined uidKey to the key "uid".
     *
     * @param array $result
     */
    protected function setResultUid(array &$result)
    {
        // If we're operating with the default uidKey there's nothing to do.
        if ($this->uidKey === "uid")
        {
            return;
        }

        if (isset($result[$this->uidKey]))
        {
            // The AccessToken expects a "uid" to have the key "uid".
            $result['uid'] = $result[$this->uidKey];
        }
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
        $errno = curl_errno($curl);
        $error = curl_error($curl);
        $response = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        if ($status != 200)
        {
            throw new \Exception($url . ' returned: ' . ($status ? "HTTP $status, content: $response" : "cURL: $errno $error"));
        }
        return $response;
    }

    protected function getAuthorizationHeaders($token)
    {
        $headers = [];
        if ($this->authorizationHeader)
        {
            $headers[] = 'Authorization: ' . $this->authorizationHeader . ' ' . $token;
        }
        return $headers;
    }

    public function getHeaders($token = null)
    {
        $headers = $this->headers;
        if ($token)
        {
            $headers = array_merge($headers, $this->getAuthorizationHeaders($token));
        }
        return $headers;
    }

    public function setRedirectHandler(callable $handler)
    {
        $this->redirectHandler = $handler;
    }
}
