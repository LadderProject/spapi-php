<?php
/*
 *  @author: BeckYang
 *  @email: snryid@163.com
 */

namespace LadderProject\Spapi\Utils;

use LadderProject\Spapi\SignerException;

class Signer
{
    public static function sign($request, array $signOptions)
    {
        //required
        $service = $signOptions['service'] ?? null;
        $accessKey = $signOptions['access_key'] ?? null;
        $secretKey = $signOptions['secret_key'] ?? null;
        $region = $signOptions['region'] ?? null;
        $host = $signOptions['host'] ?? null;
        $method = $signOptions['method'] ?? null;

        if (is_null($service)) throw new SignerException("Service is required");
        if (is_null($accessKey)) throw new SignerException("Access key is required");
        if (is_null($secretKey)) throw new SignerException("Secret key is required");
        if (is_null($region)) throw new SignerException("Region key is required");
        if (is_null($host)) throw new SignerException("Host key is required");
        if (is_null($method)) throw new SignerException("Method key is required");

        //optionl
        $accessToken = $signOptions['access_token'] ?? null;
        $securityToken = $signOptions['security_token'] ?? null;
        $userAgent = $signOptions['user_agent'] ?? 'spapi_client';
        $queryString = $signOptions['query_string'] ?? '';
        $data = $signOptions['payload'] ?? [];
        $uri = $signOptions['uri'] ?? '';

        if (is_array($data)) {
            $param = json_encode($data);
            if ($param == "[]") {
                $requestPayload = "";
            } else {
                $requestPayload = $param;
            }
        } else {
            $requestPayload = $data;
        }
        $hashedPayload = hash('sha256', $requestPayload);

        $DateTime = new \DateTime('UTC');
        $x_amz_date = $DateTime->format('Ymd\THis\Z');

        $headers = [
            'host' => $host,
            'user-agent' => $userAgent,
        ];

        if (!is_null($accessToken)) {
            $headers['x-amz-access-token'] = $accessToken;
        }
        $headers['x-amz-date'] = $x_amz_date;
        if (!is_null($securityToken)) {
            $headers['x-amz-security-token'] = $securityToken;
        }

        $canonicalHeadersStr = '';
        foreach ($headers as $k => $v) {
            $canonicalHeadersStr .= $k . ':' . $v . "\n";
        }

        $signedHeadersStr = join(';', array_keys($headers));

        $canonicalRequest = $method . "\n";
        $canonicalRequest .= $uri . "\n";
        $canonicalRequest .= $queryString . "\n";
        $canonicalRequest .= $canonicalHeadersStr . "\n";
        $canonicalRequest .= $signedHeadersStr . "\n";
        $canonicalRequest .= $hashedPayload;

        $credentialScope = $DateTime->format('Ymd') . '/' . $region . '/' . $service . '/' . 'aws4_request';

        $stringToSign = 'AWS4-HMAC-SHA256' . "\n" . $x_amz_date . "\n" . $credentialScope . "\n" . hash('sha256', $canonicalRequest);

        $sign = hash_hmac('sha256', $DateTime->format('Ymd'), 'AWS4' . $secretKey, true);
        $sign = hash_hmac('sha256', $region, $sign, true);
        $sign = hash_hmac('sha256', $service, $sign, true);
        $sign = hash_hmac('sha256', 'aws4_request', $sign, true);
        $signature = hash_hmac('sha256', $stringToSign, $sign);

        $authorizationHeader = "AWS4-HMAC-SHA256 Credential={$accessKey}/{$credentialScope}, SignedHeaders={$signedHeadersStr}, Signature={$signature}";

        $headers = array_merge($headers, ['Authorization' => $authorizationHeader]);

        $request['headers'] = array_merge($request['headers'], $headers);

        return $request;
    }
}