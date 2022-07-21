package com.changhr.utils.crypto.hash;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * MAC 摘要算法工具类
 *
 * @author changhr2013
 * @create 2019-05-08 10:53
 */
public abstract class HMAC {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * HMAC 算法类型
     */
    public static final String HMAC_MD5 = "HmacMD5";
    public static final String HMAC_SHA256 = "HmacSHA256";
    public static final String HMAC_SM3 = "HmacSM3";

    /**
     * 初始化 HmacMD5 密钥
     *
     * @return byte[] 二进制密钥
     */
    public static byte[] initHmacMD5Key() {
        return initHmacKey(HMAC_MD5);
    }

    /**
     * HmacMD5 消息摘要
     *
     * @param data 待做摘要处理的数据
     * @param key  密钥
     * @return byte[] 消息摘要
     */
    public static byte[] MD5(byte[] data, byte[] key) {
        return hmac(data, key, HMAC_MD5);
    }

    /**
     * HmacMD5 消息摘要
     *
     * @param data 待做摘要处理的数据
     * @param key  密钥
     * @return 消息摘要，hex 格式
     */
    public static String MD5ToHex(byte[] data, byte[] key) {
        return Hex.toHexString(hmac(data, key, HMAC_MD5));
    }

    /**
     * 初始化 HmacSHA256 密钥
     *
     * @return byte[] 二进制密钥
     */
    public static byte[] initHmacSHA256Key() {
        return initHmacKey(HMAC_SHA256);
    }

    /**
     * HmacSHA256 消息摘要
     *
     * @param data 待做摘要处理的数据
     * @param key  密钥
     * @return byte[] 消息摘要
     */
    public static byte[] SHA256(byte[] data, byte[] key) {
        return hmac(data, key, HMAC_SHA256);
    }

    public static String SHA256ToHex(byte[] data, byte[] key) {
        return Hex.toHexString(hmac(data, key, HMAC_SHA256));
    }

    /**
     * 初始化 HmacSM3 密钥
     *
     * @return byte[] 二进制密钥
     */
    public static byte[] initHmacSM3Key() {
        return initHmacKey(HMAC_SM3, BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param data 待做摘要的数据
     * @param key  密钥
     * @return byte[] 消息摘要
     */
    public static byte[] SM3(byte[] data, byte[] key) {
        return hmac(data, key, HMAC_SM3, BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param data 待做摘要的数据
     * @param key  密钥
     * @return hex 格式的消息摘要
     */
    public static String SM3ToHex(byte[] data, byte[] key) {
        return Hex.toHexString(hmac(data, key, HMAC_SM3, BouncyCastleProvider.PROVIDER_NAME));
    }

    /**
     * 生成 Hmac Key 通用方法
     *
     * @param algorithm Hmac 算法类型
     * @return Hmac Key
     */
    public static byte[] initHmacKey(String algorithm) {
        return initHmacKey(algorithm, null);
    }

    /**
     * 生成 Hmac Key 通用方法
     *
     * @param algorithm Hmac 算法类型
     * @param provider  jce 实现方
     * @return Hmac Key
     */
    public static byte[] initHmacKey(String algorithm, String provider) {
        KeyGenerator keyGenerator;
        try {
            if (provider == null) {
                keyGenerator = KeyGenerator.getInstance(algorithm);
            } else {
                keyGenerator = KeyGenerator.getInstance(algorithm, provider);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception: " + algorithm);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("no such provider exception: " + provider);
        }

        // 产生密钥
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 通用 Hmac 摘要方法
     *
     * @param data      待摘要数据
     * @param key       hmac key
     * @param algorithm 算法类型
     * @return Hmac 消息摘要
     */
    public static byte[] hmac(byte[] data, byte[] key, String algorithm) {
        return hmac(data, key, algorithm, null);
    }

    /**
     * 通用 Hmac 摘要方法
     *
     * @param dataBytes 待摘要数据
     * @param keyBytes  hmac key
     * @param algorithm 算法类型
     * @param provider  jce 实现方
     * @return Hmac 消息摘要
     */
    public static byte[] hmac(byte[] dataBytes, byte[] keyBytes, String algorithm, String provider) {
        // 还原密钥
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        // 实例化 Mac
        Mac mac;
        try {
            if (provider == null) {
                mac = Mac.getInstance(secretKeySpec.getAlgorithm());
            } else {
                mac = Mac.getInstance(secretKeySpec.getAlgorithm(), provider);
            }
            // 初始化 Mac
            mac.init(secretKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception: " + algorithm);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("no such provider exception: " + provider);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("invalid key exception");
        }
        // 执行消息摘要
        return mac.doFinal(dataBytes);
    }
}
