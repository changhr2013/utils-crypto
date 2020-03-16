package com.changhr.utils.crypto.hash;

import com.changhr.utils.crypto.hash.sm3.SM3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

/**
 * MAC 摘要算法工具类
 *
 * @author changhr
 * @create 2019-05-08 10:53
 */
@SuppressWarnings({"WeakerAccess"})
public abstract class HMACUtil {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            new SM3.Mappings().configure(provider);
        }
    }

    /**
     * Hmac 算法类型
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
     * 初始化 Hex 形式的 HmacMD5 密钥
     *
     * @return hex 格式的密钥
     */
    public static String initHmacMD5KeyHex() {
        return Hex.toHexString(initHmacMD5Key());
    }

    /**
     * 初始化 base64 形式的 HmacMD5 密钥
     *
     * @return base64 格式的密钥
     */
    public static String initHmacMD5KeyBase64() {
        return Base64.getEncoder().encodeToString(initHmacMD5Key());
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

    public static String MD5ToBase64(byte[] data, byte[] key) {
        return Base64.getEncoder().encodeToString(MD5(data, key));
    }

    public static String MD5ToHex(byte[] data, byte[] key) {
        return Hex.toHexString(MD5(data, key));
    }

    public static byte[] MD5WithHexKey(String text, String hexKey) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = Hex.decode(hexKey);
        return MD5(data, key);
    }

    public static String MD5WithHexKeyToBase64(String text, String hexKey) {
        return Base64.getEncoder().encodeToString(MD5WithHexKey(text, hexKey));
    }

    public static String MD5WithHexKeyToHex(String text, String hexKey) {
        return Hex.toHexString(MD5WithHexKey(text, hexKey));
    }

    public static byte[] MD5WithBase64Key(String text, String base64Key) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = Base64.getDecoder().decode(base64Key);
        return MD5(data, key);
    }

    public static String MD5WithBase64KeyToBase64(String text, String base64Key) {
        return Base64.getEncoder().encodeToString(MD5WithBase64Key(text, base64Key));
    }

    public static String MD5WithBase64KeyToHex(String text, String base64Key) {
        return Hex.toHexString(MD5WithBase64Key(text, base64Key));
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
     * 初始化 Hex 形式的 HmacSHA256 密钥
     *
     * @return hex 格式的密钥
     */
    public static String initHmacSHA256KeyHex() {
        return Hex.toHexString(initHmacSHA256Key());
    }

    /**
     * 初始化 base64 形式的 HmacSHA256 密钥
     *
     * @return base64 格式的密钥
     */
    public static String initHmacSHA256KeyBase64() {
        return Base64.getEncoder().encodeToString(initHmacSHA256Key());
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

    public static String SHA256ToBase64(byte[] data, byte[] key) {
        return Base64.getEncoder().encodeToString(SHA256(data, key));
    }

    public static String SHA256ToHex(byte[] data, byte[] key) {
        return Hex.toHexString(SHA256(data, key));
    }

    public static byte[] SHA256WithHexKey(String text, String hexKey) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = Hex.decode(hexKey);
        return SHA256(data, key);
    }

    public static String SHA256WithHexKeyToBase64(String text, String hexKey) {
        return Base64.getEncoder().encodeToString(SHA256WithHexKey(text, hexKey));
    }

    public static String SHA256WithHexKeyToHex(String text, String hexKey) {
        return Hex.toHexString(SHA256WithHexKey(text, hexKey));
    }

    public static byte[] SHA256WithBase64Key(String text, String base64Key) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = Base64.getDecoder().decode(base64Key);
        return SHA256(data, key);
    }

    public static String SHA256WithBase64KeyToBase64(String text, String base64Key) {
        return Base64.getEncoder().encodeToString(SHA256WithBase64Key(text, base64Key));
    }

    public static String SHA256WithBase64KeyToHex(String text, String base64Key) {
        return Hex.toHexString(SHA256WithBase64Key(text, base64Key));
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
     * 初始化 HmacSM3 密钥
     *
     * @return hex 格式密钥
     */
    public static String initHmacSM3KeyHex() {
        return Hex.toHexString(initHmacSM3Key());
    }

    /**
     * 初始化 HmacSM3 密钥
     *
     * @return base64 格式密钥
     */
    public static String initHmacSM3KeyBase64() {
        return Base64.getEncoder().encodeToString(initHmacSM3Key());
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
     * @return base64 格式的消息摘要
     */
    public static String SM3ToBase64(byte[] data, byte[] key) {
        return Base64.getEncoder().encodeToString(SM3(data, key));
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param data 待做摘要的数据
     * @param key  密钥
     * @return hex 格式的消息摘要
     */
    public static String SM3ToHex(byte[] data, byte[] key) {
        return Hex.toHexString(SM3(data, key));
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param text   字符串格式的待摘要的数据
     * @param hexKey hex 格式的密钥
     * @return byte[] 消息摘要
     */
    public static byte[] SM3WithHexKey(String text, String hexKey) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = Hex.decode(hexKey);
        return SM3(data, key);
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param text   字符串格式的待摘要的数据
     * @param hexKey hex 格式的密钥
     * @return base64 格式的消息摘要
     */
    public static String SM3WithHexKeyToBase64(String text, String hexKey) {
        return Base64.getEncoder().encodeToString(SM3WithHexKey(text, hexKey));
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param text   字符串格式的待摘要的数据
     * @param hexKey hex 格式的密钥
     * @return hex 格式的消息摘要
     */
    public static String SM3WithHexKeyToHex(String text, String hexKey) {
        return Hex.toHexString(SM3WithHexKey(text, hexKey));
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param text      字符串格式的待摘要的数据
     * @param base64Key base64 格式的密钥
     * @return byte[] 消息摘要
     */
    public static byte[] SM3WithBase64Key(String text, String base64Key) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] key = Base64.getDecoder().decode(base64Key);
        return SM3(data, key);
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param text      字符串格式的待摘要的数据
     * @param base64Key base64 格式的密钥
     * @return base64 格式的消息摘要
     */
    public static String SM3WithBase64KeyToBase64(String text, String base64Key) {
        return Base64.getEncoder().encodeToString(SM3WithBase64Key(text, base64Key));
    }

    /**
     * HmacSM3 消息摘要
     *
     * @param text      字符串格式的待摘要的数据
     * @param base64Key base64 格式的密钥
     * @return hex 格式的消息摘要
     */
    public static String SM3WithBase64KeyToHex(String text, String base64Key) {
        return Hex.toHexString(SM3WithBase64Key(text, base64Key));
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
     * @param data      待摘要数据
     * @param key       hmac key
     * @param algorithm 算法类型
     * @param provider  jce 实现方
     * @return Hmac 消息摘要
     */
    public static byte[] hmac(byte[] data, byte[] key, String algorithm, String provider) {
        // 还原密钥
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);
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
        return mac.doFinal(data);
    }
}
