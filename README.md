This is a STANDALONE SIMPLIFIED fork of https://github.com/thephpleague/oauth2-client/

cURL is used instead of Guzzle, some useless wrapper code is removed. Tests still pass.

# OAuth 2.0 Client

This package makes it stupidly simple to integrate your application with OAuth 2.0 identity providers.

Everyone is used to seeing those "Connect with Facebook/Google/etc" buttons around the Internet and social network
integration is an important feature of most web-apps these days. Many of these sites use an Authentication and Authorization standard called OAuth 2.0.

It will work with any OAuth 2.0 provider (be it an OAuth 2.0 Server for your own API or Facebook) and provides support
for popular systems out of the box. This package abstracts out some of the subtle but important differences between various providers, handles access tokens and refresh tokens, and allows you easy access to profile information on these other sites.

## Requirements

The following versions of PHP are supported.

* PHP 5.4
* PHP 5.5
* PHP 5.6
* PHP 7.0
* HHVM

## Usage

### Authorization Code Flow

```php
$provider = new \OAuth2\<ProviderName>([
    'clientId'      => 'XXXXXXXX',
    'clientSecret'  => 'XXXXXXXX',
    'redirectUri'   => 'https://your-registered-redirect-uri/',
    'scopes'        => ['email', '...', '...'],
]);

// For example, with simplest GenericProvider and Keycloak
$provider = new \OAuth2\GenericProvider([
    'clientId'      => 'XXXXXXXX',
    'clientSecret'  => 'XXXXXXXX',
    'urlAuthorize'   => 'http://keycloak-server/auth/realms/example/protocol/openid-connect/auth',
    'urlAccessToken' => 'http://keycloak-server/auth/realms/example/protocol/openid-connect/token',
    'urlUserDetails' => 'http://keycloak-server/auth/realms/example/protocol/openid-connect/userinfo',
    'scopes'         => ['name', 'email'],
]);

$useJWT = false;
$jwksEndpointURL = '';

if (!isset($_GET['code']))
{
    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->state;
    header('Location: '.$authUrl);
    exit;
}
elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state']))
{
    // Check given state against previously stored one to mitigate CSRF attack
    unset($_SESSION['oauth2state']);
    exit('Invalid state');
}
else
{
    // Try to get an access token (using the authorization code grant)
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Optional: Now you have a token you can look up a users profile data
    try
    {
        if (!$useJWT)
        {
            // We got an access token, let's now get the user's details
            $userDetails = $provider->getUserDetails($token);
        }
        else
        {
            // If your tokens are JWT (JSON Web Tokens) (Keycloak's ones are),
            // you may decode and verify them instead of fetching user details from server
            $keys = \OAuth2\JWT::extractKeys(json_decode(file_get_contents($jwksEndpointURL), true));
            $userDetails = JWT::decode($token->accessToken, $keys);

            // You may also just decode it without verifying
            $userDetails = JWT::decode($token->accessToken, NULL);
        }

        // Use these details to create a new profile
        printf('Hello %s!', $userDetails['firstname']);

        var_dump($userDetails);
    }
    catch (Exception $e)
    {
        // Failed to get user details
        exit('Oh dear...');
    }

    // Use this to interact with an API on the users behalf
    echo $token->accessToken;

    // Use this to get a new access token if the old one expires
    echo $token->refreshToken;

    // Number of seconds until the access token will expire, and need refreshing
    echo $token->expires;
}
```

### Refreshing a Token

```php
$provider = new \OAuth2\<ProviderName>([
    'clientId'      => 'XXXXXXXX',
    'clientSecret'  => 'XXXXXXXX',
    'redirectUri'   => 'https://your-registered-redirect-uri/',
]);

$token = $provider->getAccessToken('refresh_token', ['refresh_token' => $refreshToken]);
```

### Built-In Providers

This package currently has built-in support for:

- Basic GenericProvider suitable for any OAuth2 server
- Eventbrite
- Facebook
- Github
- Google
- Instagram
- LinkedIn
- Microsoft

These are as many OAuth 2 services as we plan to support officially. Maintaining a wide selection of providers
damages our ability to make this package the best it can be, especially as we progress towards v1.0.

### Third-Party Providers

If you would like to support other providers, please make them available as a Composer package, then link to them
below.

These providers allow integration with other providers not supported by `oauth2-client`. They may require an older version
so please help them out with a pull request if you notice this.

- [Auth0](https://github.com/RiskioFr/oauth2-auth0)
- [Battle.net](https://packagist.org/packages/depotwarehouse/oauth2-bnet)
- [Coinbase](https://github.com/openclerk/coinbase-oauth2)
- [Dropbox](https://github.com/pixelfear/oauth2-dropbox)
- [FreeAgent](https://github.com/CloudManaged/oauth2-freeagent)
- [Google Nest](https://github.com/JC5/nest-oauth2-provider)
- [Mail.ru](https://packagist.org/packages/aego/oauth2-mailru)
- [Meetup](https://github.com/howlowck/meetup-oauth2-provider)
- [Naver](https://packagist.org/packages/deminoth/oauth2-naver)
- [Odnoklassniki](https://packagist.org/packages/aego/oauth2-odnoklassniki)
- [Square](https://packagist.org/packages/wheniwork/oauth2-square)
- [Twitch.tv](https://github.com/tpavlek/oauth2-twitch)
- [Uber](https://github.com/stevenmaguire/oauth2-uber)
- [Vkontakte](https://packagist.org/packages/j4k/oauth2-vkontakte)
- [Yandex](https://packagist.org/packages/aego/oauth2-yandex)
- [ZenPayroll](https://packagist.org/packages/wheniwork/oauth2-zenpayroll)

### Implementing your own provider

If you are working with an oauth2 service not supported out-of-the-box or by an existing package, it is quite simple to
implement your own. Simply extend `\OAuth2\AbstractProvider` and implement the required abstract
methods:

```php
abstract public function urlAuthorize();
abstract public function urlAccessToken();
abstract public function urlUserDetails(\OAuth2\AccessToken $token);
abstract public function userDetails($response, \OAuth2\AccessToken $token);
```

Each of these abstract methods contain a docblock defining their expectations and typical behaviour. Once you have
extended this class, you can simply follow the example above using your new `Provider`.

#### Custom account identifiers in access token responses

Some OAuth2 Server implementations include a field in their access token response defining some identifier
for the user account that just requested the access token. In many cases this field, if present, is called "uid", but
some providers define custom identifiers in their response. If your provider uses a nonstandard name for the "uid" field,
when extending the AbstractProvider, in your new class, define a property `public $uidKey` and set it equal to whatever
your provider uses as its key. For example, Battle.net uses `accountId` as the key for the identifier field, so in that
provider you would add a property:

```php
public $uidKey = 'accountId';
```

## Install

Via Composer

``` bash
$ composer require vitalif/oauth2-client
```

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Credits

- [Vitaliy Filippov](https://github.com/vitalif) - this simplified version
- [Alex Bilbie](https://github.com/alexbilbie)
- [Ben Corlett](https://github.com/bencorlett)
- [James Mills](https://github.com/jamesmills)
- [Phil Sturgeon](https://github.com/philsturgeon)
- [Tom Anderson](https://github.com/TomHAnderson)
- [All Contributors](https://github.com/thephpleague/oauth2-client/contributors)

## License

The MIT License (MIT). Please see [License File](https://github.com/vitalif/oauth2-client/blob/master/LICENSE) for more information.
