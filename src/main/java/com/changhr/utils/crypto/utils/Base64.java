package com.changhr.utils.crypto.utils;

import java.nio.charset.StandardCharsets;

/**
 * Base64 编/解码工具类
 *
 * @author changhr2013
 */
public class Base64 {

    private Base64() {
    }

    /**
     * Base64 编码
     *
     * @param src 待编码的字节数组
     * @return 编码后的 Base64 字符串
     */
    public static String encodeToString(byte[] src) {
        return java.util.Base64.getEncoder().encodeToString(src);
    }

    /**
     * Base64 解码
     *
     * @param src 待解码的 Base64 字符串
     * @return 解码后的字节数组
     */
    public static byte[] decode(String src) {
        return java.util.Base64.getDecoder().decode(src);
    }

    /**
     * 字符串 Base64 编码
     *
     * @param src 待编码的原文字符串，UTF-8 格式
     * @return 编码后的 Base64 字符串
     */
    public static String encodeUtf8ToString(String src) {
        return java.util.Base64.getEncoder().encodeToString(src.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 字符串 Base64 解码
     *
     * @param src 待解码的 Base64 字符串
     * @return 解码后的字符串，UTF-8 格式
     */
    public static String decodeToUtf8(String src) {
        return new String(java.util.Base64.getDecoder().decode(src), StandardCharsets.UTF_8);
    }

}
