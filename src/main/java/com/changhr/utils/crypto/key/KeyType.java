package com.changhr.utils.crypto.key;

/**
 * 密钥二进制编码类型枚举
 *
 * @author changhr2013
 */
public enum KeyType {

    /**
     * ASN1 编码形式
     */
    PRIVATE_KEY_PKCS8("PKCS#8 Private Key"),
    PRIVATE_KEY_PKCS1_RSA("PKCS#1 Private Key"),
    PRIVATE_KEY_SEC1_EC("SEC1 Private Key"),
    PRIVATE_KEY_PLAIN_SM2("SM2 Plain Private Key"),
    PUBLIC_KEY_X509("X.509 Public Key"),
    PUBLIC_KEY_PLAIN_SM2("SM2 Plain Public Key"),
    CERTIFICATE_X509("X.509 Certificate");

    private String codec;

    KeyType(String codec) {
        this.codec = codec;
    }

    public String getCodec() {
        return codec;
    }
}
