package com.changhr.utils.crypto.utils;

import java.security.SecureRandom;

/**
 * 随机数工具类
 *
 * @author changhr2013
 */
public class RandomUtil {

    public RandomUtil() {
    }

    public static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (Exception e) {
            return new SecureRandom();
        }
    }

    public static byte[] generateNonce(int size) {
        SecureRandom secureRandom = getSecureRandom();
        byte[] nonce = new byte[size];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    public static byte[] generateGCMNonce() {
        SecureRandom secureRandom = getSecureRandom();
        byte[] nonce = new byte[96 / Byte.SIZE];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

}
