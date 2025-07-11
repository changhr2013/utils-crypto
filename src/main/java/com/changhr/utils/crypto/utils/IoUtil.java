package com.changhr.utils.crypto.utils;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

/**
 * IO Utils 参考自 Hutool
 *
 * @author changhr2013
 */
public class IoUtil {

    private IoUtil() {
    }

    /**
     * 获取文件 UTF-8 BufferedReader (字符串路径)
     *
     * @param pathStr 文件路径字符串
     * @return BufferedReader 对象
     * @throws IOException 如果文件读取失败
     */
    public static BufferedReader getUtf8Reader(String pathStr) throws IOException {
        return getUtf8Reader(Paths.get(pathStr));
    }

    /**
     * 获取文件 UTF-8 BufferedReader
     *
     * @param path 文件路径
     * @return BufferedReader 对象
     * @throws IOException 如果文件读取失败
     */
    public static BufferedReader getUtf8Reader(Path path) throws IOException {
        return getReader(path, StandardCharsets.UTF_8);
    }

    /**
     * 获取文件 BufferedReader
     *
     * @param path    文件路径
     * @param charset 字符集
     * @return BufferedReader 对象
     * @throws IOException 如果文件读取失败
     */
    public static BufferedReader getReader(Path path, Charset charset) throws IOException {
        Objects.requireNonNull(path, "文件路径不能为 null");
        Charset actualCharset = charset != null ? charset : StandardCharsets.UTF_8;
        return Files.newBufferedReader(path, actualCharset);
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
     * 获得一个 Reader
     *
     * @param in      输入流
     * @param charset 字符集
     * @return BufferedReader 对象
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
     * String 转为 UTF-8 编码的字节流流
     *
     * @param content 内容
     * @return 字节流
     */
    public static ByteArrayInputStream toUtf8Stream(String content) {
        return toStream(content, StandardCharsets.UTF_8);
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
        }
        byte[] bytes = null == charset ? content.getBytes() : content.getBytes(charset);
        return toStream(bytes);
    }

    /**
     * 文件转为 InputStream
     *
     * @param path 文件路径
     * @return InputStream
     * @throws IOException 如果文件不存在或读取失败
     */
    public static InputStream toStream(Path path) throws IOException {
        Objects.requireNonNull(path, "文件路径不能为null");
        return Files.newInputStream(path, StandardOpenOption.READ);
    }

    /**
     * 文件转为 {@link FileInputStream}
     *
     * @param file 文件
     * @return {@link FileInputStream}
     * @throws UncheckedIOException 如果文件不存在
     */
    public static FileInputStream toStream(File file) {
        Objects.requireNonNull(file, "文件不能为 null");
        try {
            return new FileInputStream(file);
        } catch (FileNotFoundException e) {
            throw new UncheckedIOException("文件不存在: " + file.getAbsolutePath(), e);
        }
    }

    /**
     * byte[] 转为 {@link ByteArrayInputStream}
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

    /**
     * 读取 InputStream 为 UTF-8 字符串
     *
     * @param inputStream 输入流
     * @return 字符串内容
     * @throws IOException 如果读取失败
     */
    public static String toUtf8String(InputStream inputStream) throws IOException {
        return toString(inputStream, StandardCharsets.UTF_8);
    }

    /**
     * 读取 InputStream 为字符串
     *
     * @param inputStream 输入流
     * @param charset     字符集
     * @return 字符串内容
     * @throws IOException 如果读取失败
     */
    public static String toString(InputStream inputStream, Charset charset) throws IOException {
        Objects.requireNonNull(inputStream, "输入流不能为 null");
        Charset actualCharset = charset != null ? charset : StandardCharsets.UTF_8;

        try (BufferedReader reader = getReader(inputStream, actualCharset);
             StringWriter writer = new StringWriter()) {

            char[] buffer = new char[8192];
            int charsRead;
            while ((charsRead = reader.read(buffer)) != -1) {
                writer.write(buffer, 0, charsRead);
            }

            return writer.toString();
        }
    }

    /**
     * 复制输入流到输出流
     *
     * @param source 源输入流
     * @param target 目标输出流
     * @return 复制的字节数
     * @throws IOException 如果复制失败
     */
    public static long copy(InputStream source, OutputStream target) throws IOException {
        Objects.requireNonNull(source, "源输入流不能为 null");
        Objects.requireNonNull(target, "目标输出流不能为 null");

        byte[] buffer = new byte[8192];
        long totalBytes = 0;
        int bytesRead;

        while ((bytesRead = source.read(buffer)) != -1) {
            target.write(buffer, 0, bytesRead);
            totalBytes += bytesRead;
        }

        return totalBytes;
    }
}
