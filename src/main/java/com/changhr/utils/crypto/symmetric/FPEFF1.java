package com.changhr.utils.crypto.symmetric;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * FPE 格式保留加密
 *
 * @author changhr2013
 * @date 2021/9/5
 */
public class FPEFF1 {

    /**
     * FPE FF1 基础加密，PRF 使用 AES 算法
     *
     * @param plainBytes  明文，byte[] 格式
     * @param keyBytes    加密使用的密钥，byte[] 格式
     * @param tWeak       tWeak
     * @param radix       基数
     * @return 密文，byte[] 格式
     */
    public static byte[] encrypt(byte[] plainBytes, byte[] keyBytes, byte[] tWeak, int radix) {
        AESEngine aesEngine = new AESEngine();
        return encrypt(plainBytes, keyBytes, tWeak, radix, aesEngine);
    }

    /**
     * FPE FF1 基础解密，PRF 使用 AES 算法
     *
     * @param cipherBytes 密文，byte[] 格式
     * @param keyBytes    加密使用的密钥，byte[] 格式
     * @param tWeak       tWeak
     * @param radix       基数
     * @return 明文，byte[] 格式
     */
    public static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes, byte[] tWeak, int radix) {
        AESEngine aesEngine = new AESEngine();
        return decrypt(cipherBytes, keyBytes, tWeak, radix, aesEngine);
    }

    /**
     * FPE FF1 基础加密
     *
     * @param plainBytes  明文，byte[] 格式
     * @param keyBytes    加密使用的密钥，byte[] 格式
     * @param tWeak       tWeak
     * @param radix       基数
     * @param blockCipher 作为 PRF 的对称加密算法
     * @return 密文，byte[] 格式
     */
    public static byte[] encrypt(byte[] plainBytes, byte[] keyBytes, byte[] tWeak, int radix, BlockCipher blockCipher) {

        FPEFF1Engine fpeff1Engine = new FPEFF1Engine(blockCipher);
        FPEParameters fpeParameters = new FPEParameters(new KeyParameter(keyBytes), radix, tWeak);
        fpeff1Engine.init(true, fpeParameters);

        byte[] cipherBytes = new byte[plainBytes.length];
        fpeff1Engine.processBlock(plainBytes, 0, plainBytes.length, cipherBytes, 0);
        return cipherBytes;
    }

    /**
     * FPE FF1 基础解密
     *
     * @param cipherBytes 密文，byte[] 格式
     * @param keyBytes    加密使用的密钥，byte[] 格式
     * @param tWeak       tWeak
     * @param radix       基数
     * @param blockCipher 作为 PRF 的对称加密算法
     * @return 明文，byte[] 格式
     */
    public static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes, byte[] tWeak, int radix, BlockCipher blockCipher) {
        FPEFF1Engine fpeff1Engine = new FPEFF1Engine(blockCipher);
        FPEParameters fpeParameters = new FPEParameters(new KeyParameter(keyBytes), radix, tWeak);
        fpeff1Engine.init(false, fpeParameters);

        byte[] plainBytes = new byte[cipherBytes.length];
        fpeff1Engine.processBlock(cipherBytes, 0, cipherBytes.length, plainBytes, 0);
        return plainBytes;
    }
}
