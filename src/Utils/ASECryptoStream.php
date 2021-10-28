<?php
/*
 *  @author: BeckYang
 *  @email: snryid@163.com
 */

namespace LadderProject\Spapi\Utils;

class ASECryptoStream
{
    public const CIPHER = 'AES256';

    public static function encrypt(string $plainText, string $key, string $iv): string
    {
        return openssl_encrypt($plainText, static::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    }

    public static function decrypt(string $encryptedText, string $key, string $iv): string
    {
        return openssl_decrypt($encryptedText, static::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    }
}