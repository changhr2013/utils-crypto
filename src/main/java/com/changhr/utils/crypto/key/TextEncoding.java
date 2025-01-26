package com.changhr.utils.crypto.key;

/**
 * 二进制文本编码类型枚举
 *
 * @author changhr2013
 */
public enum TextEncoding {
    /**
     * 编码形式
     */
    BASE64("Base64"),
    HEX("Hex"),
    PEM("PEM");

    private final String name;

    TextEncoding(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
