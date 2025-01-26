package com.changhr.utils.crypto.key;

import org.bouncycastle.util.encoders.Hex;

import java.util.Base64;
import java.util.function.Function;

/**
 * 文本编解码器枚举
 *
 * @author changhr2013
 */
public enum TextCodec {

    /**
     * 编码形式
     */
    BASE64("Base64", (bytes) -> Base64.getEncoder().encodeToString(bytes), (str) -> Base64.getDecoder().decode(str)),
    HEX("Hex", Hex::toHexString, Hex::decode);

    private final String name;

    private final Function<byte[], String> encodeFunc;

    private final Function<String, byte[]> decodeFunc;

    TextCodec(String name, Function<byte[], String> encodeFunc, Function<String, byte[]> decodeFunc) {
        this.name = name;
        this.encodeFunc = encodeFunc;
        this.decodeFunc = decodeFunc;
    }

    public String getName() {
        return name;
    }

    public Function<byte[], String> getEncodeFunc() {
        return encodeFunc;
    }

    public Function<String, byte[]> getDecodeFunc() {
        return decodeFunc;
    }
}
