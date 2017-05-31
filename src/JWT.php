<?php

namespace OAuth2;

/**
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  Authentication_JWT
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @author   Vitaliy Filippov <vitalif@mail.ru>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt (forked from here)
 */
class JWT
{
    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static $leeway = 0;

    /**
     * Allow the current timestamp to be specified.
     * Useful for fixing a value within unit testing.
     *
     * Will default to PHP time() value if null.
     */
    public static $timestamp = null;

    public static $supported_algs = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
    );

    /**
     * Extract keys from JWKS response structure
     * { keys: [ { kid, kty, alg, use, n, e }, ... ] }
     *
     * For example, from Keycloak's "certs" endpoint URL:
     * http://your-keycloak-server.com/auth/realms/your-realm/protocol/openid-connect/certs
     */
    public static function extractKeys(array $jwks)
    {
        if (!isset($jwks['keys']) || !is_array($jwks['keys']))
        {
            return NULL;
        }
        $keys = [];
        foreach ($jwks['keys'] as $key)
        {
            if (!isset($key['kid']) || !isset($key['kty']))
            {
                continue;
            }
            if ($key['kty'] == 'RSA')
            {
                if (!isset($key['n']) || !isset($key['e']))
                {
                    continue;
                }
                $keys[$key['kid']] = JWT_RSAPubKey::modexp2openssl($key['n'], $key['e']);
            }
            elseif ($key['kty'] == 'oct')
            {
                if (!isset($key['k']))
                {
                    continue;
                }
                $keys[$key['kid']] = $key['k'];
            }
        }
        return $keys;
    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string            $jwt    The JWT
     * @param string|array|null $key    The key, or map of keys.
     *                                  If the algorithm used is asymmetric, this is the public key
     *                                  If empty, no verification is performed
     *
     * @return object The JWT's payload as a PHP object
     *
     * @throws UnexpectedValueException         Provided JWT was invalid
     * @throws JWT_SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws JWT_BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws JWT_BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws JWT_ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode($jwt, $key)
    {
        $timestamp = is_null(static::$timestamp) ? time() : static::$timestamp;

        $tks = explode('.', $jwt);
        if (count($tks) != 3)
        {
            throw new \UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64))))
        {
            throw new \UnexpectedValueException('Invalid header encoding');
        }
        if (null === $payload = static::jsonDecode(static::urlsafeB64Decode($bodyb64)))
        {
            throw new \UnexpectedValueException('Invalid claims encoding');
        }
        $sig = static::urlsafeB64Decode($cryptob64);

        if ($key)
        {
            if (empty($header['alg']))
            {
                throw new \UnexpectedValueException('Empty algorithm');
            }
            if (empty(static::$supported_algs[$header['alg']]))
            {
                throw new \UnexpectedValueException('Algorithm not supported');
            }
            if (is_array($key) || $key instanceof \ArrayAccess)
            {
                if (isset($header['kid']))
                {
                    $key = $key[$header['kid']];
                }
                else
                {
                    throw new \UnexpectedValueException('"kid" empty, unable to lookup correct key');
                }
            }
            // Check the signature
            if (!static::verify("$headb64.$bodyb64", $sig, $key, $header['alg']))
            {
                throw new JWT_SignatureInvalidException('Signature verification failed');
            }
        }

        // Check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload['nbf']) && $payload['nbf'] > ($timestamp + static::$leeway))
        {
            throw new JWT_BeforeValidException(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['nbf'])
            );
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload['iat']) && $payload['iat'] > ($timestamp + static::$leeway))
        {
            throw new JWT_BeforeValidException(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['iat'])
            );
        }

        // Check if this token has expired.
        if (isset($payload['exp']) && ($timestamp - static::$leeway) >= $payload['exp'])
        {
            throw new JWT_ExpiredException('Expired token');
        }

        return $payload;
    }

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array  $payload    PHP object or array
     * @param string        $key        The secret key.
     *                                  If the algorithm used is asymmetric, this is the private key
     * @param string        $alg        The signing algorithm.
     *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     * @param mixed         $keyId
     * @param array         $head       An array with header elements to attach
     *
     * @return string A signed JWT
     *
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $alg);
        if ($keyId !== null)
        {
            $header['kid'] = $keyId;
        }
        if (isset($head) && is_array($head))
        {
            $header = array_merge($head, $header);
        }
        $segments = array();
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = static::sign($signing_input, $key, $alg);
        $segments[] = static::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string            $msg    The message to sign
     * @param string|resource   $key    The secret key
     * @param string            $alg    The signing algorithm.
     *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     *
     * @return string An encrypted message
     *
     * @throws DomainException Unsupported algorithm was specified
     */
    public static function sign($msg, $key, $alg = 'HS256')
    {
        if (empty(static::$supported_algs[$alg]))
        {
            throw new \DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = static::$supported_algs[$alg];
        if ($function == 'hash_hmac')
        {
            return hash_hmac($algorithm, $msg, $key, true);
        }
        elseif ($function == 'openssl')
        {
            $signature = '';
            $success = openssl_sign($msg, $signature, $key, $algorithm);
            if (!$success)
                throw new \DomainException("OpenSSL unable to sign data");
            else
                return $signature;
        }
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string            $msg        The original message (header and body)
     * @param string            $signature  The original signature
     * @param string|resource   $key        For HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string            $alg        The algorithm
     *
     * @return bool
     *
     * @throws DomainException Invalid Algorithm or OpenSSL failure
     */
    private static function verify($msg, $signature, $key, $alg)
    {
        if (empty(static::$supported_algs[$alg]))
        {
            throw new \DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = static::$supported_algs[$alg];
        if ($function == 'openssl')
        {
            $success = openssl_verify($msg, $signature, $key, $algorithm);
            if (!$success)
                throw new \DomainException("OpenSSL unable to verify data: " . openssl_error_string());
            else
                return $signature;
        }
        else /* if ($function == 'hash_hmac') */
        {
            $hash = hash_hmac($algorithm, $msg, $key, true);
            if (function_exists('hash_equals'))
            {
                return hash_equals($signature, $hash);
            }
            $len = min(strlen($signature), strlen($hash));

            $status = 0;
            for ($i = 0; $i < $len; $i++)
                $status |= (ord($signature[$i]) ^ ord($hash[$i]));
            $status |= (strlen($signature) ^ strlen($hash));

            return ($status === 0);
        }
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     *
     * @throws DomainException Provided string was invalid JSON
     */
    public static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4))
        {
            /** In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
             * to specify that large ints (like Steam Transaction IDs) should be treated as
             * strings, rather than the PHP default behaviour of converting them to floats.
             */
            $obj = json_decode($input, true, 512, JSON_BIGINT_AS_STRING);
        }
        else
        {
            /** Not all servers will support that, however, so for older versions we must
             * manually detect large ints in the JSON string and quote them (thus converting
             *them to strings) before decoding, hence the preg_replace() call.
             */
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints, true);
        }

        if (function_exists('json_last_error') && $errno = json_last_error())
        {
            static::handleJsonError($errno);
        }
        elseif ($obj === null && $input !== 'null')
        {
            throw new \DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Encode a PHP object into a JSON string.
     *
     * @param object|array $input A PHP object or array
     *
     * @return string JSON representation of the PHP object or array
     *
     * @throws DomainException Provided object could not be encoded to valid JSON
     */
    public static function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error())
        {
            static::handleJsonError($errno);
        }
        elseif ($json === 'null' && $input !== null)
        {
            throw new \DomainException('Null result with non-null input');
        }
        return $json;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder)
        {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        );
        throw new \DomainException(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }
}

class JWT_BeforeValidException extends \UnexpectedValueException
{

}

class JWT_ExpiredException extends \UnexpectedValueException
{

}

class JWT_SignatureInvalidException extends \UnexpectedValueException
{

}

class JWT_RSAPubKey
{
    protected static function asn1length($len)
    {
        if ($len < 0x80)
            return chr($len);
        elseif ($len < 0x100)
            return chr(0x81) . chr($len);
        elseif ($len < 0x10000)
            return chr(0x82) . chr(0xFF & ($len >> 8)) . chr(0xFF & $len);
        elseif ($len < 0x1000000)
            return chr(0x83) . chr(0xFF & ($len >> 16)) . chr(0xFF & ($len >> 8)) . chr(0xFF & $len);
        else
            return chr(0x84) . chr(0xFF & ($len >> 24)) . chr(0xFF & ($len >> 16)) . chr(0xFF & ($len >> 8)) . chr(0xFF & $len);
    }

    protected static function asn1int($int)
    {
        $int = (ord($int{0}) > 0x7f ? "\x00" : "") . $int;
        return "\x02" . self::asn1length(strlen($int)) . $int;
    }

    protected static function asn1seq($elem1, $elem2)
    {
        return "\x30" . self::asn1length(strlen($elem1) + strlen($elem2)) . $elem1 . $elem2;
    }

    protected static function asn1bitstring($elem)
    {
        $elem = "\x00" . $elem;
        return "\x03" . self::asn1length(strlen($elem)) . $elem;
    }

    /**
     * Convert modulus + exponent ('n', 'e' fields from JWK) to OpenSSL RSA public key format
     */
    public static function modexp2openssl($mod, $exp)
    {
        $rsaid = hex2bin('300D06092A864886F70D0101010500');
        $exp = base64_decode(str_replace([ '-', '_' ], [ '+', '/' ], $exp), true);
        $mod = base64_decode(str_replace([ '-', '_' ], [ '+', '/' ], $mod), true);
        if (!$mod || !$exp)
            return '';
        $pk = self::asn1seq($rsaid, self::asn1bitstring(self::asn1seq(self::asn1int($mod), self::asn1int($exp))));
        $pk = base64_encode($pk);
        $pk = preg_replace('/(.{64})/', "\$1\n", $pk);
        $pk = "-----BEGIN PUBLIC KEY-----\n$pk\n-----END PUBLIC KEY-----\n";
        return $pk;
    }
}
