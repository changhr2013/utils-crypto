package com.changhr.utils.crypto.symmetric;

import com.changhr.utils.crypto.asymmetric.SM2Util;
import com.changhr.utils.crypto.utils.PaddingUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Map;

/**
 * 国密 SM4 对称加密算法工具类
 *
 * @author changhr
 * @create 2019-05-08 10:21
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public abstract class SM4Util {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 密钥算法
     */
    public static final String KEY_ALGORITHM = "SM4";

    /**
     * 密钥的字节长度
     */
    public static final int KEY_LENGTH = 16;

    /**
     * 密钥位长度
     */
    public static final int KEY_SIZE = 128;

    /**
     * 加解密算法/工作模式/填充方式
     * Java 7 支持 PKCS5Padding 填充方式
     * Bouncy Castle 支持 PKCS7Padding 填充方式
     */
    public static final String ECB_PKCS_5_PADDING = "SM4/ECB/PKCS5Padding";
    public static final String ECB_NO_PADDING = "SM4/ECB/NoPadding";

    /**
     * 生成 SM4 对称密钥
     *
     * @return SM4 对称密钥，长度为 128 位
     */
    public static byte[] initKey() {
        // 实例化
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm exception: " + KEY_ALGORITHM, e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("no such provider exception: " + BouncyCastleProvider.PROVIDER_NAME, e);
        }
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * SM4 对称密钥加密
     *
     * @param keyBytes SM4对称密钥
     * @param plain    待加密数据
     * @return byte[]  加密后的数据
     */
    public static byte[] encrypt(byte[] keyBytes, byte[] plain) {
        return encrypt(keyBytes, plain, ECB_PKCS_5_PADDING);
    }

    /**
     * SM4 对称密钥加密
     *
     * @param keyBytes        SM4对称密钥
     * @param plain           待加密数据
     * @param cipherAlgorithm 加解密算法/工作模式/填充方式
     * @return byte[]  加密后的数据
     */
    public static byte[] encrypt(byte[] keyBytes, byte[] plain, final String cipherAlgorithm) {
        if (keyBytes.length != KEY_LENGTH) {
            throw new RuntimeException("error key length");
        }
        try {
            Key key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(cipherAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // 发现使用 NoPadding 时，使用 ZeroPadding 填充
            if (ECB_NO_PADDING.equals(cipherAlgorithm)) {
                return cipher.doFinal(PaddingUtil.formatWithZeroPadding(plain, cipher.getBlockSize()));
            }

            return cipher.doFinal(plain);
        } catch (Exception e) {
            throw new RuntimeException("sm4 encrypt error", e);
        }
    }

    /**
     * SM4 对称密钥解密
     *
     * @param keyBytes SM4 对称密钥
     * @param cipher   待解密的数据
     * @return byte[]  解密后的数据
     */
    public static byte[] decrypt(byte[] keyBytes, byte[] cipher) {
        return decrypt(keyBytes, cipher, ECB_PKCS_5_PADDING);
    }

    /**
     * SM4 对称密钥解密
     *
     * @param keyBytes        SM4 对称密钥
     * @param cipher          待解密的数据
     * @param cipherAlgorithm 加解密算法/工作模式/填充方式
     * @return byte[]  解密后的数据
     */
    public static byte[] decrypt(byte[] keyBytes, byte[] cipher, final String cipherAlgorithm) {
        if (keyBytes.length != KEY_LENGTH) {
            throw new RuntimeException("error key length");
        }
        try {
            Key key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            Cipher in = Cipher.getInstance(cipherAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            in.init(Cipher.DECRYPT_MODE, key);

            // 发现使用 NoPadding 时，使用 ZeroPadding 填充
            if (ECB_NO_PADDING.equals(cipherAlgorithm)) {
                return PaddingUtil.removeZeroPadding(in.doFinal(cipher), in.getBlockSize());
            }

            return in.doFinal(cipher);
        } catch (Exception e) {
            throw new RuntimeException("sm4 decrypt error", e);
        }
    }

    public static void main(String[] args) {

        byte[] data = "hello world!".getBytes(StandardCharsets.UTF_8);

        Map<String, Object> keyMap = SM2Util.initKey();
        byte[] sm2PrivateKey = SM2Util.getSwapPrivateKey(keyMap);
        System.out.println(Hex.toHexString(sm2PrivateKey));

        byte[] sm4Key = SM4Util.initKey();

        byte[] encrypt = SM4Util.encrypt(sm4Key, sm2PrivateKey, ECB_NO_PADDING);
        System.out.println(Hex.toHexString(encrypt));

        byte[] decrypt = SM4Util.decrypt(sm4Key, encrypt, ECB_NO_PADDING);
        System.out.println(Hex.toHexString(decrypt));
    }
}
