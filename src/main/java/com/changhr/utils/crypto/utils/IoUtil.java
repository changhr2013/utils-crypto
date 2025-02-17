package com.changhr.utils.crypto.utils;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * IO Utils 移植自 Hutool
 *
 * @author changhr2013
 */
public class IoUtil {

    private IoUtil() {
    }

    /**
     * 获得一个文件读取器，默认使用 UTF-8 编码
     *
     * @param in 输入流
     * @return BufferedReader 对象
     */
    public static BufferedReader getUtf8Reader(InputStream in) {
        return getReader(in, StandardCharsets.UTF_8);
    }

    /**
     * 获得一个文件读取器
     *
     * @param in          输入流
     * @param charsetName 字符集名称
     */
    public static BufferedReader getReader(InputStream in, String charsetName) {
        return getReader(in, Charset.forName(charsetName));
    }

    /**
     * 获得一个 Reader
     *
     * @param in      输入流
     * @param charset 字符集
     * @return BufferedReader对象
     */
    public static BufferedReader getReader(InputStream in, Charset charset) {
        if (null == in) {
            return null;
        }

        InputStreamReader reader;
        if (null == charset) {
            reader = new InputStreamReader(in);
        } else {
            reader = new InputStreamReader(in, charset);
        }

        return new BufferedReader(reader);
    }

    /**
     * String 转为流
     *
     * @param content     内容
     * @param charsetName 编码
     * @return 字节流
     */
    public static ByteArrayInputStream toStream(String content, String charsetName) {
        return toStream(content, Charset.forName(charsetName));
    }

    /**
     * String 转为流
     *
     * @param content 内容
     * @param charset 编码
     * @return 字节流
     */
    public static ByteArrayInputStream toStream(String content, Charset charset) {
        if (content == null) {
            return null;
        } else {
            byte[] bytes = null == charset ? content.getBytes() : content.getBytes(charset);
            return toStream(bytes);
        }
    }

    /**
     * String 转为 UTF-8 编码的字节流流
     *
     * @param content 内容
     * @return 字节流
     */
    public static ByteArrayInputStream toUtf8Stream(String content) {
        return toStream(content, StandardCharsets.UTF_8);
    }

    /**
     * 文件转为{@link FileInputStream}
     *
     * @param file 文件
     * @return {@link FileInputStream}
     */
    public static FileInputStream toStream(File file) {
        try {
            return new FileInputStream(file);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * byte[] 转为{@link ByteArrayInputStream}
     *
     * @param content 内容 bytes
     * @return 字节流
     */
    public static ByteArrayInputStream toStream(byte[] content) {
        if (content == null) {
            return null;
        }
        return new ByteArrayInputStream(content);
    }
}
