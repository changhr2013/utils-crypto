package com.changhr.utils.crypto.symmetric;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * AES 对称加密算法工具类
 *
 * @author changhr2013
 * @create 2019-05-08 9:29
 */
public abstract class AES {

    /**
     * 密钥算法类型
     */
    public static final String KEY_ALGORITHM = "AES";

    /**
     * 密钥的默认位长度
     */
    public static final int KEY_SIZE = 256;

    /**
     * 加解密算法/工作模式/填充方式
     */
    public static final String ECB_NO_PADDING = "AES/ECB/NoPadding";
    public static final String ECB_PKCS_7_PADDING = "AES/ECB/PKCS7Padding";

    public static final String CBC_NO_PADDING = "AES/CBC/NoPadding";
    public static final String CBC_PKCS_7_PADDING = "AES/CBC/PKCS7Padding";

    public static final String CTR_NO_PADDING = "AES/CTR/NoPadding";
    public static final String GCM_NO_PADDING = "AES/GCM/NoPadding";

    /**
     * 转换密钥
     *
     * @param key 二进制密钥
     * @return Key 密钥
     */
    private static Key toKey(byte[] key) {
        // 实例化 AES 密钥材料
        return new SecretKeySpec(key, KEY_ALGORITHM);
    }

    /**
     * 加密
     *
     * @param plainBytes      待加密数据
     * @param keyBytes        密钥
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 加密后的密文
     */
    public static byte[] encrypt(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes, final String cipherAlgorithm) {
        if (ECB_NO_PADDING.equalsIgnoreCase(cipherAlgorithm) || ECB_PKCS_7_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.encryptByECB(plainBytes, keyBytes, cipherAlgorithm);
        }

        if (GCM_NO_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.encryptByGCM(plainBytes, keyBytes, ivBytes, null, cipherAlgorithm);
        }

        return BCCipher.encrypt(plainBytes, keyBytes, ivBytes, cipherAlgorithm);
    }

    /**
     * 解密
     *
     * @param cipherBytes     待解密数据
     * @param keyBytes        密钥
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 解密的数据
     */
    public static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes, final String cipherAlgorithm) {
        if (ECB_NO_PADDING.equalsIgnoreCase(cipherAlgorithm) || ECB_PKCS_7_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.decryptByECB(cipherBytes, keyBytes, cipherAlgorithm);
        }

        if (GCM_NO_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.decryptByGCM(cipherBytes, keyBytes, ivBytes, null, cipherAlgorithm);
        }

        return BCCipher.decrypt(cipherBytes, keyBytes, ivBytes, cipherAlgorithm);
    }

    /**
     * 生成密钥
     * 不指定密钥长度，默认为 256 位
     *
     * @return byte[] 二进制密钥
     */
    public static byte[] initKey() {
        return initKey(KEY_SIZE);
    }

    /**
     * 生成密钥
     * 128、192、256 可选
     *
     * @param keySize 密钥长度
     * @return byte[] 二进制密钥
     */
    public static byte[] initKey(int keySize) {
        // AES 要求密钥长度为 128 位、192 位或 256 位
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new RuntimeException("error keySize: " + keySize);
        }
        // 实例化
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception: " + KEY_ALGORITHM, e);
        }
        keyGenerator.init(keySize);
        // 生成秘密密钥
        SecretKey secretKey = keyGenerator.generateKey();
        // 获得密钥的二进制编码形式
        return secretKey.getEncoded();
    }

}
