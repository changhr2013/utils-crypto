package com.changhr.utils.crypto.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * @author changhr
 * @create 2020-04-27 11:41
 */
public class ChaCha20Util {

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
        SecureRandom random;
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception.", e);
        }
        byte[] nonce = new byte[8];
        random.nextBytes(nonce);
        return nonce;
    }

    /**
     * ChaCha20 对称密钥加密
     *
     * @param keyBytes ChaCha20 对称密钥
     * @param plain    待加密数据
     * @return byte[]  加密后的数据
     */
    public static byte[] encrypt(byte[] keyBytes, byte[] plain, byte[] iv) {
        if (keyBytes.length != DEFAULT_KEY_SIZE / Byte.SIZE && keyBytes.length != 256 / Byte.SIZE) {
            throw new RuntimeException("error key length");
        }
        try {
            Key key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher out = Cipher.getInstance(CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            out.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            return out.doFinal(plain);
        } catch (Exception e) {
            throw new RuntimeException("chacha20 encrypt error", e);
        }
    }

    /**
     * ChaCha20 对称密钥解密
     *
     * @param keyBytes ChaCha20 对称密钥
     * @param cipher   待解密的数据
     * @return byte[]  解密后的数据
     */
    public static byte[] decrypt(byte[] keyBytes, byte[] cipher, byte[] iv) {
        if (keyBytes.length != DEFAULT_KEY_SIZE / Byte.SIZE && keyBytes.length != 256 / Byte.SIZE) {
            throw new RuntimeException("error key length");
        }
        try {
            Key key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            Cipher in = Cipher.getInstance(CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            in.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return in.doFinal(cipher);
        } catch (Exception e) {
            throw new RuntimeException("chacha20 decrypt error", e);
        }
    }

    public static void main(String[] args) {

        byte[] key = initKey();
        byte[] iv = generateIv();
        System.out.println("key: " + Hex.toHexString(key));
        System.out.println("iv: " + Hex.toHexString(iv));

        byte[] data = "helloworld".getBytes(StandardCharsets.UTF_8);

        byte[] encryptData = encrypt(key, data, iv);
        System.out.println("encrypt: " + Hex.toHexString(encryptData));

        byte[] decryptData = decrypt(key, encryptData, iv);
        System.out.println("decrypt: " + new String(decryptData, StandardCharsets.UTF_8));
    }

}
