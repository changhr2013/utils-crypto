package com.changhr.utils.crypto.utils;

/**
 * Hex 编/解码工具类
 *
 * @author changhr2013
 */
public class Hex {

    /**
     * Hex 编码
     *
     * @param data 待编码的字节数组
     * @return 编码后的 Hex 字符串
     */
    public static String toHexString(byte[] data) {
        return org.bouncycastle.util.encoders.Hex.toHexString(data);
    }

    /**
     * 解码 Hex 编码的字符串数据（空格将被忽略）
     *
     * @param data 待解码的 Hex 字符串
     * @return 解码后的字节数组
     */
    public static byte[] decode(String data) {
        return org.bouncycastle.util.encoders.Hex.decode(data);
    }
}
