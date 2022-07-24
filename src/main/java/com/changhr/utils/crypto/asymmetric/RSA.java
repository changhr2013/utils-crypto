package com.changhr.utils.crypto.asymmetric;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA 非对称加密算法工具类
 *
 * @author changhr2013
 * @create 2019-05-08 14:52
 */
public abstract class RSA {

    /**
     * 密钥算法类型
     */
    public static final String KEY_ALGORITHM = "RSA";

    public static final String ECB_NO_PADDING = "RSA/ECB/NoPadding";
    public static final String ECB_PKCS_1_PADDING = "RSA/ECB/PKCS1Padding";

    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    /**
     * 公钥
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";

    /**
     * 私钥
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * RSA 密钥长度，默认 2048 位
     * 密钥长度必须是 64 的倍数，范围在 512 ~ 65535 位之间
     */
    private static final int KEY_SIZE = 2048;

    /**
     * 签名
     *
     * @param dataBytes       待签名数据
     * @param privateExponent 私钥指数
     * @param modulus         模数
     * @return byte[] 数字签名
     */
    public static byte[] sign(byte[] dataBytes, byte[] privateExponent, byte[] modulus) {

        BigInteger modulusBigint = new BigInteger(1, modulus);
        BigInteger privateExponentBigint = new BigInteger(1, privateExponent);
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulusBigint, privateExponentBigint);
        try {
            // 实例化密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 获取私钥对象
            PrivateKey privateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);
            return sign(dataBytes, privateKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 签名
     *
     * @param dataBytes  待签名数据
     * @param privateKey 私钥，{@link PrivateKey}
     * @return byte[] 数字签名
     */
    public static byte[] sign(byte[] dataBytes, PrivateKey privateKey) {
        try {
            // 实例化密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 实例化 Signature
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            // 初始化 Signature
            signature.initSign(privateKey);
            // 更新
            signature.update(dataBytes);
            // 签名
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 验签
     *
     * @param data           待验签数据
     * @param sign           数字签名
     * @param publicExponent 公钥指数
     * @param modulus        模数
     * @return boolean 验签通过返回 true，失败返回 false
     */
    public static boolean verify(byte[] data, byte[] sign, byte[] publicExponent, byte[] modulus) {
        BigInteger modulusBigint = new BigInteger(1, modulus);
        BigInteger publicExponentBigint = new BigInteger(1, publicExponent);
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulusBigint, publicExponentBigint);
        try {
            // 实例化密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 生成公钥
            PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
            return verify(data, sign, publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 验签
     *
     * @param data      待验签数据
     * @param publicKey 公钥，{@link PublicKey}
     * @param sign      数字签名
     * @return boolean 验签通过返回 true，失败返回 false
     */
    public static boolean verify(byte[] data, byte[] sign, PublicKey publicKey) {
        try {
            // 实例化 Signature
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            // 初始化 Signature
            signature.initVerify(publicKey);
            // 更新
            signature.update(data);
            // 验证
            return signature.verify(sign);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 公钥加密
     *
     * @param plainBytes     待加密数据
     * @param publicKeyBytes 公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] plainBytes, byte[] publicKeyBytes, final String cipherAlgorithm) {
        // 获取公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 生成公钥
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            // 对数据解密
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plainBytes);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 私钥解密
     *
     * @param cipherBytes     待解密数据
     * @param privateKeyBytes 私钥
     * @param cipherAlgorithm 算法/工作模式/填充方式
     * @return byte[] 解密数据
     */
    public static byte[] decrypt(byte[] cipherBytes, byte[] privateKeyBytes, final String cipherAlgorithm) {
        // 获取私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 生成私钥
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            // 对数据解密
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(cipherBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取私钥
     *
     * @param keyMap 密钥 Map
     * @return byte[] 私钥
     */
    public static byte[] getPrivateKey(Map<String, Key> keyMap) {
        PrivateKey key = (PrivateKey) keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    /**
     * 获取公钥
     *
     * @param keyMap 密钥 Map
     * @return byte[] 公钥
     */
    public static byte[] getPublicKey(Map<String, Key> keyMap) {
        PublicKey key = (PublicKey) keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }

    /**
     * 初始化密钥
     * 默认密钥长度为 2048 位
     *
     * @return 密钥 Map
     */
    public static Map<String, Key> initKey() {
        return initKey(KEY_SIZE);
    }

    /**
     * 初始化密钥
     *
     * @param keySize 密钥长度
     * @return 密钥 Map
     */
    public static Map<String, Key> initKey(int keySize) {
        // 生成密钥对
        KeyPair keyPair = initKeyPair(keySize);
        // 封装密钥 Map
        Map<String, Key> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());
        return keyMap;
    }

    public static KeyPair initKeyPair(int keySize) {
        // 实例化密钥对生成器
        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm: " + KEY_ALGORITHM, e);
        }
        // 初始化密钥对生成器
        keyPairGen.initialize(keySize);
        // 生成密钥对
        return keyPairGen.generateKeyPair();
    }

}
