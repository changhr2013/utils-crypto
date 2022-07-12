package com.changhr.utils.crypto.symmetric;

import com.changhr.utils.crypto.utils.RandomUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * ChaCha20 加解密工具类
 *
 * @author changhr2013
 * @create 2020-04-27 11:41
 */
public class ChaCha20 {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * 密钥算法
     */
    public static final String KEY_ALGORITHM = "ChaCha";

    /**
     * 密钥位长度
     */
    public static final int DEFAULT_KEY_SIZE = 128;

    /**
     * 加解密算法/工作模式/填充方式
     */
    public static final String CIPHER_ALGORITHM = "ChaCha";

    /**
     * 生成 ChaCha20 对称密钥
     *
     * @return ChaCha20 对称密钥，128 位，16 个字节
     */
    public static byte[] initKey() {
        return initKey(DEFAULT_KEY_SIZE);
    }

    /**
     * 生成 ChaCha20 对称密钥
     *
     * @return ChaCha20 对称密钥
     */
    public static byte[] initKey(int keySize) {
        // ChaCha20 要求密钥长度为 128 位或 256 位
        if (keySize != 128 && keySize != 256) {
            throw new RuntimeException("error keySize: " + keySize);
        }
        // 实例化
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception: " + KEY_ALGORITHM, e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("no such provider exception: " + BouncyCastleProvider.PROVIDER_NAME, e);
        }
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 生成 IV 向量
     *
     * @return byte[]，8 个字节
     */
    public static byte[] generateIv() {
        return RandomUtil.generateNonce(8);
    }

    /**
     * ChaCha20 对称密钥加密
     *
     * @param plainBytes 待加密数据
     * @param keyBytes   ChaCha20 对称密钥
     * @param ivBytes    向量
     * @return byte[]  加密后的数据
     */
    public static byte[] encrypt(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes) {
        if (keyBytes.length != DEFAULT_KEY_SIZE / Byte.SIZE && keyBytes.length != 256 / Byte.SIZE) {
            throw new RuntimeException("error key length");
        }
        try {
            Key key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            Cipher out = Cipher.getInstance(CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            out.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            return out.doFinal(plainBytes);
        } catch (Exception e) {
            throw new RuntimeException("chacha20 encrypt error", e);
        }
    }

    /**
     * ChaCha20 对称密钥解密
     *
     * @param keyBytes    ChaCha20 对称密钥
     * @param cipherBytes 待解密的数据
     * @param ivBytes     向量
     * @return byte[]  解密后的数据
     */
    public static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes) {
        if (keyBytes.length != DEFAULT_KEY_SIZE / Byte.SIZE && keyBytes.length != 256 / Byte.SIZE) {
            throw new RuntimeException("error key length");
        }
        try {
            Key key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            Cipher in = Cipher.getInstance(CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            in.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return in.doFinal(cipherBytes);
        } catch (Exception e) {
            throw new RuntimeException("chacha20 decrypt error", e);
        }
    }

}
