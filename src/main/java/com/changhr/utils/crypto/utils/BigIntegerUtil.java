package com.changhr.utils.crypto.utils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

/**
 * BigInteger 工具类
 *
 * @author changhr
 * @create 2020-03-13 10:25
 */
public class BigIntegerUtil {

    private BigIntegerUtil() {
    }

    public static String toBase64(BigInteger bigint) {
        return bigint == null ? null : Base64.getEncoder().encodeToString(bigIntegerToBytes(bigint));
    }

    public static String toHex(BigInteger bigint) {
        return bigint == null ? null : bigint.toString(16);
    }

    public static BigInteger fromBase64(String base64) {
        if (base64 == null) {
            return null;
        } else {
            return bigIntegerFromBytes(Base64.getDecoder().decode(base64));
        }
    }

    public static BigInteger fromHex(String hex) {
        if (hex == null) {
            return null;
        } else {
            try {
                return new BigInteger(hex, 16);
            } catch (NumberFormatException e) {
                return null;
            }
        }
    }

    public static BigInteger bigIntegerFromBytes(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    public static byte[] bigIntegerToBytes(BigInteger bigint) {
        assert bigint.signum() != -1;
        byte[] bytes = bigint.toByteArray();
        return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }
}
