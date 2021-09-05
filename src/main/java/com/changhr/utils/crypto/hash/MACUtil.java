package com.changhr.utils.crypto.hash;

import com.changhr.utils.crypto.provider.UnlimitedHolder;
import com.changhr.utils.crypto.symmetric.AESUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * @author changhr
 * @create 2019-10-15 14:14
 */
public class MACUtil {

    static {
        UnlimitedHolder.init();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        }
    }

    public static final String KEY_ALGORITHM = "AES";

    public static final String AES_C_MAC = "AESCMAC";

    public static final String AES_G_MAC = "AESGMAC";

    public static final String AES_CCM_MAC = "AESCCMMAC";

    /**
     * 转换密钥
     *
     * @param key 二进制密钥
     * @return Key 密钥
     */
    private static Key toKey(byte[] key) {
        // 实例化 DES 密钥材料
        return new SecretKeySpec(key, KEY_ALGORITHM);
    }

    /**
     * 使用 C-MAC 计算 MAC
     *
     * @param key  密钥
     * @param data 待进行 C-MAC 的数据
     * @return byte[] C-MAC 的结果
     */
    public static byte[] generateCMac(byte[] key, byte[] data) {
        return generateMac(key, data, AES_C_MAC, false);
    }

    /**
     * 使用 G-MAC 计算 MAC
     *
     * @param key  密钥
     * @param data 待进行 G-MAC 的数据
     * @return byte[] G-MAC 的结果
     */
    public static byte[] generateGMac(byte[] key, byte[] data) {
        return generateMac(key, data, AES_G_MAC, true);
    }

    /**
     * 使用 CCM-MAC 计算 MAC
     *
     * @param key  密钥
     * @param data 待进行 CCM-MAC 的数据
     * @return byte[] CCM-MAC 的结果
     */
    public static byte[] generateCCMMac(byte[] key, byte[] data) {
        return generateMac(key, data, AES_CCM_MAC, true);
    }

    private static byte[] generateMac(byte[] key, byte[] data, final String algorithm, boolean hasIV) {
        Key k = toKey(key);
        Mac mac;
        try {
            mac = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            if (hasIV) {
                mac.init(k, new IvParameterSpec(Hex.decode("000102030405060708090a0b")));
            } else {
                mac.init(k);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(data);
    }

    public static void main(String[] args) {
        byte[] key = AESUtil.initKey(128);

        byte[] sign1 = MACUtil.generateCMac(key, "hello world!".getBytes(StandardCharsets.UTF_8));
        System.out.println(Hex.toHexString(sign1));

        byte[] sign2 = MACUtil.generateGMac(key, "hello world!".getBytes(StandardCharsets.UTF_8));
        System.out.println(Hex.toHexString(sign2));

        byte[] sign3 = MACUtil.generateCCMMac(key, "hello world!".getBytes(StandardCharsets.UTF_8));
        System.out.println(Hex.toHexString(sign3));
    }
}
