<?php

declare(strict_types=1);

namespace IEXBase\TronAPI\Support;

use kornrunner\Secp256k1;
use kornrunner\Signature\Signature;

class Secp
{
    public static function sign(string $message, string $privateKey): string
    {
        $secp = new Secp256k1();

        /** @var Signature $sign */
        $sign = $secp->sign($message, $privateKey, ['canonical' => false]);

        return $sign->toHex() . bin2hex(implode('', array_map('chr', [$sign->getRecoveryParam()])));
    }

    public static function verify(string $message, string $signature, string $address): bool
    {
        if (strlen($signature) < 2) {
            return false;
        }

        $hash = Hash::SHA256($message);

        $secp = new Secp256k1();
        $len = strlen($signature);
        $recovery = ord(hex2bin(substr($signature, $len - 2)));
        $signature = substr($signature, 0, $len - 2);

        try {
            $publicKey = $secp->recoverPublic($hash, $signature, $recovery);
            $recoveredAddress = self::publicKeyToAddress($publicKey);
            return strtolower($address) === strtolower($recoveredAddress);
        } catch (\Exception $e) {
            return false;
        }
    }

    private static function publicKeyToAddress(string $publicKey): string
    {
        $hash = Keccak::hash(hex2bin($publicKey), 256);
        $hash = substr($hash, 24);
        return Base58Check::encode($hash, 0x41);
    }
}
