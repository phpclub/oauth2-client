<?php

namespace OAuth2;

class CurlMock
{
    static $pending = [];
    static function addPendingResponse($exec_ok, $status_line, $headers, $body)
    {
        self::$pending[] = [ $exec_ok, $status_line, $headers, $body ];
    }

    var $options = [];
    var $response = [];
    function __construct($response)
    {
        $this->response = $response;
    }
}

function curl_init()
{
    if (!CurlMock::$pending)
    {
        return false;
    }
    return new CurlMock(array_shift(CurlMock::$pending));
}

function curl_setopt_array($curl, $array)
{
    $curl->options = $array + $curl->options;
}

function curl_exec($curl)
{
    if (!$curl->response[0])
    {
        return false;
    }
    if (!empty($curl->options[CURLOPT_RETURNTRANSFER]))
    {
        if (!empty($curl->options[CURLOPT_HEADER]))
        {
            return trim($curl->response[2])."\n\n".$curl->response[3];
        }
        return $curl->response[3];
    }
    return true;
}

function curl_close($curl)
{
}

function curl_getinfo($curl, $opt)
{
    if ($opt == CURLINFO_HTTP_CODE)
    {
        return intval($curl->response[1]);
    }
    return false;
}
