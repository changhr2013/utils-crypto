package com.changhr.utils.crypto.hash;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * hash 摘要算法工具类
 *
 * @author changhr
 * @create 2019-05-08 12:45
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public abstract class HASHUtil {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static final String HASH_MD5 = "MD5";

    public static final String HASH_SHA1 = "SHA-1";

    public static final String HASH_SHA256 = "SHA-256";

    public static final String HASH_SM3 = "SM3";

    /**
     * MD5 消息摘要
     * @param data  待做摘要处理的数据
     * @return  byte[] 消息摘要
     */
    public static byte[] MD5(byte[] data) {
        return hash(data, HASH_MD5);
    }

    public static byte[] MD5(String text) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return MD5(data);
    }

    public static String MD5Hex(byte[] data) {
        return Hex.toHexString(MD5(data));
    }

    public static String MD5Hex(String text) {
        return Hex.toHexString(MD5(text));
    }

    /**
     * SHA-1 消息摘要
     * @param data  待做摘要处理的数据
     * @return  byte[] 消息摘要
     */
    public static byte[] SHA1(byte[] data) {
        return hash(data, HASH_SHA1);
    }

    public static byte[] SHA1(String text) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return SHA1(data);
    }

    public static String SHA1Hex(byte[] data) {
        return Hex.toHexString(SHA1(data));
    }

    public static String SHA1Hex(String text) {
        return Hex.toHexString(SHA1(text));
    }

    /**
     * SHA-256 消息摘要
     * @param data  待做摘要处理的数据
     * @return  byte[] 消息摘要
     */
    public static byte[] SHA256(byte[] data) {
        return hash(data, HASH_SHA256);
    }

    public static byte[] SHA256(String text) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return SHA256(data);
    }

    public static String SHA256Hex(byte[] data) {
        return Hex.toHexString(SHA256(data));
    }

    public static String SHA256Hex(String text) {
        return Hex.toHexString(SHA256(text));
    }

    /**
     * SM3 消息摘要
     *
     * @param data 待 hash 的数据
     * @return byte[] SM3 hash 值
     */
    public static byte[] SM3(byte[] data) {
        return hash(data, HASH_SM3, BouncyCastleProvider.PROVIDER_NAME);
    }

    public static byte[] SM3(String text) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return SM3(data);
    }

    public static String SM3Hex(byte[] data) {
        return Hex.toHexString(SM3(data));
    }

    public static String SM3Hex(String text) {
        return Hex.toHexString(SM3(text));
    }

    /**
     * 通用消息摘要
     * @param data          待做摘要的数据
     * @param hashAlgorithm 摘要的算法类型
     * @return  byte[] 消息摘要
     */
    private static byte[] hash(byte[] data, final String hashAlgorithm) {
        // 初始化 MessageDigest
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception: " + hashAlgorithm, e);
        }
        // 执行消息摘要
        return digest.digest(data);
    }

    /**
     * 通用消息摘要
     * @param data          待做摘要的数据
     * @param hashAlgorithm 摘要的算法类型
     * @param provider      jce 的提供者
     * @return  byte[] 消息摘要
     */
    private static byte[] hash(byte[] data, final String hashAlgorithm, String provider) {
        // 初始化 MessageDigest
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(hashAlgorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception: " + hashAlgorithm, e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("no such provider exception: " + provider, e);
        }
        // 执行消息摘要
        return digest.digest(data);
    }
}
