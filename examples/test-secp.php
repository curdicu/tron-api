<?php

require_once '../vendor/autoload.php';

use IEXBase\TronAPI\Support\Secp;
use IEXBase\TronAPI\Support\Hash;
use IEXBase\TronAPI\Support\Utils;
use IEXBase\TronAPI\Support\Keccak;
use IEXBase\TronAPI\Support\Base58Check;

// 临时定义调试函数，输出地址验证过程
function debugVerify($messageHash, $signature, $expectedAddress)
{
    // 从签名中提取恢复参数和实际签名
    $len = strlen($signature);
    $recovery = ord(hex2bin(substr($signature, $len - 2)));
    $signature = substr($signature, 0, $len - 2);

    echo "恢复参数: {$recovery}\n";

    // 创建GMP数学适配器
    $math = new \Mdanter\Ecc\Math\GmpMath();

    // 创建椭圆曲线生成器
    $generator = \Mdanter\Ecc\Curves\CurveFactory::getGeneratorByName(\Mdanter\Ecc\Curves\SecgCurve::NAME_SECP_256K1);
    $curve = $generator->getCurve();

    // 解析签名
    $signatureSerializer = new \kornrunner\Serializer\HexSignatureSerializer();
    $sig = $signatureSerializer->parse($signature);

    // 获取签名的r和s值
    $r = $sig->getR();
    $s = $sig->getS();

    echo "签名 r: " . gmp_strval($r, 16) . "\n";
    echo "签名 s: " . gmp_strval($s, 16) . "\n";

    // 将消息哈希转为GMP对象
    $e = gmp_init($messageHash, 16);

    // 获取曲线的阶和模数
    $n = $generator->getOrder();
    $fieldSize = $curve->getPrime();

    // 计算曲线点
    $isYEven = ($recovery & 1) !== 0;
    $isSecondKey = ($recovery >> 1) === 1;

    echo "isYEven: " . ($isYEven ? 'true' : 'false') . "\n";
    echo "isSecondKey: " . ($isSecondKey ? 'true' : 'false') . "\n";

    // 使用 add 和 mod 替代 addMod
    $x = $isSecondKey ? $math->add($r, $n) : $r;
    $x = $math->mod($x, $fieldSize);

    echo "恢复的 x 坐标: " . gmp_strval($x, 16) . "\n";

    // 根据x坐标计算y坐标
    try {
        $y = $curve->recoverYfromX($isYEven, $x);
        echo "恢复的 y 坐标: " . gmp_strval($y, 16) . "\n";

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
        $serializer = new \Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer($math);
        $publicKey = $serializer->serialize($Q);

        echo "恢复的公钥: {$publicKey}\n";

        // 验证公钥哈希
        $publicKeyNoPrefix = substr($publicKey, 2); // 去掉 04 前缀
        $keccak = Keccak::hash(hex2bin($publicKeyNoPrefix), 256);

        echo "Keccak 哈希: {$keccak}\n";

        $addressHex = '41' . substr($keccak, 24);
        echo "地址十六进制: {$addressHex}\n";

        $recoveredAddress = Base58Check::encode($addressHex, 0, false);
        echo "恢复的地址: {$recoveredAddress}\n";
        echo "期望的地址: {$expectedAddress}\n";
        echo "地址匹配: " . (strtolower($recoveredAddress) === strtolower($expectedAddress) ? '是' : '否') . "\n";

        return $recoveredAddress;
    } catch (\Exception $e) {
        echo "错误: " . $e->getMessage() . "\n";
        return null;
    }
}

// 生成新的密钥对并验证签名
function generateAndTest()
{
    // 生成私钥
    $privateKeyBytes = random_bytes(32);
    $privateKey = bin2hex($privateKeyBytes);

    // 创建椭圆曲线生成器
    $generator = \Mdanter\Ecc\Curves\CurveFactory::getGeneratorByName(\Mdanter\Ecc\Curves\SecgCurve::NAME_SECP_256K1);

    // 创建私钥对象
    $keySerializer = new \kornrunner\Serializer\HexPrivateKeySerializer($generator);
    $key = $keySerializer->parse($privateKey);

    // 获取公钥
    $pubKey = $key->getPublicKey()->getPoint();
    $x = gmp_strval($pubKey->getX(), 16);
    $y = gmp_strval($pubKey->getY(), 16);

    // 确保 x 和 y 坐标的长度是 64 位
    $x = str_pad($x, 64, '0', STR_PAD_LEFT);
    $y = str_pad($y, 64, '0', STR_PAD_LEFT);

    // 未压缩格式的公钥
    $publicKey = '04' . $x . $y;

    // 计算地址
    $keccak = Keccak::hash(hex2bin($x . $y), 256);
    $addressHex = '41' . substr($keccak, 24);
    $address = Base58Check::encode($addressHex, 0, false);

    // 要签名的消息
    $message = 'Hello, Tron!';
    $messageHash = bin2hex(Hash::SHA256($message));
    // $messageHash = $message;

    echo "消息: {$message}\n";
    echo "消息哈希: {$messageHash}\n";
    echo "私钥: {$privateKey}\n";
    echo "公钥: {$publicKey}\n";
    echo "地址: {$address}\n";

    // 签名消息
    $signature = Secp::sign($messageHash, $privateKey);
    echo "签名: {$signature}\n";

    // 自定义验证流程，输出调试信息
    // $recoveredAddress = debugVerify($messageHash, $signature, $address);

    // 验证签名
    $isValid = Secp::verify($messageHash, $signature, $address);
    echo "签名验证结果: " . ($isValid ? '有效' : '无效') . "\n";

    return ($isValid ? '有效' : '无效');
}

// 生成并测试，最多尝试5次
$maxAttempts = 5;
$attempt = 1;
$result = 'invalid';

while ($attempt <= $maxAttempts && $result != '有效') {
    echo "尝试 {$attempt} / {$maxAttempts}\n";
    $result = generateAndTest();
    $attempt++;

    if ($result != '有效') {
        echo "\n再次尝试...\n\n";
    }
}
