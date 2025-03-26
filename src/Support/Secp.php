<?php

declare(strict_types=1);

namespace IEXBase\TronAPI\Support;

use kornrunner\Secp256k1;
use kornrunner\Signature\Signature;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\SecgCurve;
use Mdanter\Ecc\Math\GmpMath;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use kornrunner\Serializer\HexSignatureSerializer;

/**
 * Secp256k1 椭圆曲线签名操作类
 * 
 * 提供了使用 secp256k1 椭圆曲线进行消息签名和验证的方法
 */
class Secp
{
    /**
     * 使用私钥对消息哈希进行签名
     *
     * @param string $messageHash 消息哈希（十六进制格式）
     * @param string $privateKey 私钥（十六进制格式）
     * @return string 签名结果（十六进制格式）+ 恢复ID
     */
    public static function sign(string $messageHash, string $privateKey): string
    {
        $secp = new Secp256k1();

        /** @var Signature $sign */
        $sign = $secp->sign($messageHash, $privateKey, ['canonical' => false]);

        // 将恢复参数附加到签名末尾
        return $sign->toHex() . bin2hex(implode('', array_map('chr', [$sign->getRecoveryParam()])));
    }

    /**
     * 验证签名是否有效
     *
     * @param string $messageHash 消息哈希（十六进制格式）
     * @param string $signature 签名（十六进制格式）
     * @param string $address Tron 地址（Base58Check格式）
     * @return bool 签名是否有效
     */
    public static function verify(string $messageHash, string $signature, string $address): bool
    {
        if (strlen($signature) < 2) {
            return false;
        }

        try {
            // 从签名中提取恢复参数和实际签名
            $len = strlen($signature);
            $recovery = ord(hex2bin(substr($signature, $len - 2)));
            $signature = substr($signature, 0, $len - 2);
            
            // 恢复公钥
            $publicKey = self::recoverPublicKey($messageHash, $signature, $recovery);
            if (!$publicKey) {
                return false;
            }
            
            // 根据公钥计算地址
            $recoveredAddress = self::publicKeyToAddress($publicKey);
            return strtolower($address) === strtolower($recoveredAddress);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * 从签名恢复公钥
     *
     * 使用椭圆曲线的签名恢复算法从签名中恢复公钥
     *
     * @param string $messageHash 消息哈希（十六进制格式）
     * @param string $signature 签名（十六进制格式）
     * @param int $recoveryId 恢复ID参数 (0-3)
     * @return string|null 恢复的公钥（十六进制格式），失败时返回 null
     */
    private static function recoverPublicKey(string $messageHash, string $signature, int $recoveryId): ?string
    {
        try {
            // 创建GMP数学适配器
            $math = new GmpMath();
            
            // 创建椭圆曲线生成器
            $generator = CurveFactory::getGeneratorByName(SecgCurve::NAME_SECP_256K1);
            $curve = $generator->getCurve();
            
            // 解析签名
            $signatureSerializer = new HexSignatureSerializer();
            $sig = $signatureSerializer->parse($signature);
            
            // 获取签名的r和s值
            $r = $sig->getR();
            $s = $sig->getS();
            
            // 检查恢复ID是否在有效范围内
            if ($recoveryId < 0 || $recoveryId > 3) {
                return null;
            }
            
            // 将消息哈希转为GMP对象
            $e = gmp_init($messageHash, 16);
            
            // 获取曲线的阶
            $n = $generator->getOrder();
            
            // 计算曲线点
            $isYEven = ($recoveryId & 1) !== 0;
            $isSecondKey = ($recoveryId >> 1) === 1;
            $fieldSize = $curve->getPrime();
            
            // 根据恢复ID计算 x 坐标
            $x = $isSecondKey ? $math->add($r, $n) : $r;
            $x = $math->mod($x, $fieldSize);
            
            // x值超出范围
            if ($math->cmp($x, $fieldSize) >= 0) {
                return null;
            }
            
            // 根据x坐标计算y坐标
            try {
                $y = $curve->recoverYfromX($isYEven, $x);
            } catch (\Exception $e) {
                return null;
            }
            
            // 创建R点
            $R = $curve->getPoint($x, $y);
            
            // 计算r的模逆
            $rInv = $math->inverseMod($r, $n);
            
            // 计算e的负数
            $eNeg = $math->mod($math->sub(gmp_init(0), $e), $n);
            
            // 计算公钥 Q = r^-1 * (sR - eG)
            $sR = $R->mul($s);
            $eG = $generator->mul($eNeg);
            $Q = $sR->add($eG)->mul($rInv);
            
            // 序列化公钥
            $serializer = new UncompressedPointSerializer($math);
            $publicKey = $serializer->serialize($Q);
            
            return $publicKey;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * 根据公钥生成 Tron 地址
     *
     * @param string $publicKey 完整的公钥（十六进制格式，包含前缀）
     * @return string Tron 地址（Base58Check 格式，以 T 开头）
     */
    private static function publicKeyToAddress(string $publicKey): string
    {
        // 如果公钥以 04 开头，表示未压缩格式，需要去掉前缀
        if (strpos($publicKey, '04') === 0) {
            $publicKey = substr($publicKey, 2);
        }
        
        // 对公钥进行 Keccak-256 哈希
        $hash = Keccak::hash(hex2bin($publicKey), 256);
        
        // 取后 20 字节 
        $hash = substr($hash, 24);
        
        // 添加前缀 41（Tron 地址前缀）
        $addressHex = '41' . $hash;
        
        // 转换为 Base58Check 格式
        return Base58Check::encode($addressHex, 0, false);
    }
}
