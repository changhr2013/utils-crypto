package com.changhr.utils.crypto.key;

/**
 * 密钥描述符，主要包含密钥的格式元信息，以便解释一个密钥是由何种【二进制编码】和【文本编码】输出的
 *
 * @author changhr2013
 */
public class KeyDescriptor {

    private KeyType keyType;

    private TextEncoding encoding;

    public KeyDescriptor(KeyType keyType, TextEncoding encoding) {
        this.keyType = keyType;
        this.encoding = encoding;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public TextEncoding getTextEncoding() {
        return encoding;
    }

    public void setTextEncoding(TextEncoding encoding) {
        this.encoding = encoding;
    }
}
