package com.changhr.utils.crypto.key;

import com.changhr.utils.crypto.asymmetric.SM2;
import com.changhr.utils.crypto.utils.PemUtil;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.Encodable;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * 密钥魔方（密钥格式转换器），支持对 PKCS#1、PKCS#8、SEC1、X509、SM2 裸公私钥等格式公私钥的互相转换
 *
 * @author changhr2013
 */
public class KeyCube {

    private KeyDescriptor descriptor;

    private String keyString;

    private Encodable encodeObj;

    private KeyCube() {
    }

    public KeyCube(KeyType keyType, String keyString) {
        // default use base64 encoding
        this(new KeyDescriptor(keyType, TextEncoding.BASE64), keyString);
    }

    public KeyCube(KeyDescriptor descriptor, String keyString) {
        this.descriptor = descriptor;
        this.keyString = keyString;

        KeyType keyType = descriptor.getKeyType();
        TextEncoding encoding = descriptor.getTextEncoding();

        try {
            byte[] keyBytes;
            if (encoding == TextEncoding.BASE64) {
                keyBytes = TextCodec.BASE64.getDecodeFunc().apply(keyString);
            } else if (encoding == TextEncoding.HEX) {
                keyBytes = TextCodec.HEX.getDecodeFunc().apply(keyString);
            } else if (encoding == TextEncoding.PEM) {
                keyBytes = PemUtil.readPemContent(new ByteArrayInputStream(keyString.getBytes(StandardCharsets.UTF_8)));
            } else {
                throw new RuntimeException("unsupported TextEncoding: " + encoding);
            }
            if (keyBytes == null || keyBytes.length == 0) {
                throw new RuntimeException("cannot parse key, maybe key is null or key encode is unsupported");
            }

            if (keyType == KeyType.PRIVATE_KEY_PKCS1_RSA) {
                // RSA PrivateKey PKCS#1 to PKCS#8
                RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(keyBytes);
                encodeObj = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), rsaPrivateKey);
            } else if (keyType == KeyType.PRIVATE_KEY_PKCS8) {
                // RSA PrivateKey PKCS#8
                encodeObj = PrivateKeyInfo.getInstance(keyBytes);
            } else if (keyType == KeyType.PRIVATE_KEY_SEC1_EC) {
                // SEC 1 PrivateKey to PKCS#8
                ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(keyBytes);
                encodeObj = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecPrivateKey.getParameters()), ecPrivateKey);
            } else if (keyType == KeyType.PRIVATE_KEY_PLAIN_SM2) {
                // SM2 Plain PrivateKey to PKCS#8
                BCECPrivateKey bcecPrivateKey = SM2.buildPrivateKey(keyBytes);
                encodeObj = PrivateKeyInfo.getInstance(bcecPrivateKey.getEncoded());
            } else if (keyType == KeyType.PUBLIC_KEY_X509) {
                // X.509 PublicKey
                encodeObj = SubjectPublicKeyInfo.getInstance(keyBytes);
            } else if (keyType == KeyType.CERTIFICATE_X509) {
                // Certificate to X.509 PublicKey
                try (ByteArrayInputStream inStream = new ByteArrayInputStream(keyBytes)) {
                    Certificate certificate = new CertificateFactory().engineGenerateCertificate(inStream);
                    PublicKey publicKey = certificate.getPublicKey();
                    encodeObj = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
                }
            } else if (keyType == KeyType.PUBLIC_KEY_PLAIN_SM2) {
                // SM2 Plain PublicKey to X.509 PublicKey
                BCECPublicKey bcecPublicKey = SM2.buildPublicKey(keyBytes);
                encodeObj = SubjectPublicKeyInfo.getInstance(bcecPublicKey.getEncoded());
            } else {
                throw new RuntimeException("unsupported key type: " + keyType);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public KeyDescriptor getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(KeyDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    public String getKeyString() {
        return keyString;
    }

    public void setKeyString(String keyString) {
        this.keyString = keyString;
    }

    public String exportKey(KeyType keyType) {
        return exportKey(new KeyDescriptor(keyType, TextEncoding.BASE64));
    }

    public String exportKey(KeyDescriptor descriptor) {
        try {
            KeyType keyType = descriptor.getKeyType();
            TextEncoding encoding = descriptor.getTextEncoding();

            // 特殊处理 PEM 编码
            if (encoding == TextEncoding.PEM) {
                if (keyType == KeyType.PRIVATE_KEY_PKCS8) {
                    // 如果明确需要输出 PKCS#8 格式的私钥，就使用 PKCS8Generator
                    return PemUtil.generatePemString(new PKCS8Generator((PrivateKeyInfo) encodeObj, null));
                } else if (keyType == KeyType.PUBLIC_KEY_X509 || keyType == KeyType.PRIVATE_KEY_PKCS1_RSA || keyType == KeyType.PRIVATE_KEY_SEC1_EC) {
                    // JcaMiscPEMGenerator 内部实现会自动移除 PKCS#8 的包装，输出为对应的 PKCS#1 或 SEC1
                    return PemUtil.generatePemString(new JcaMiscPEMGenerator(encodeObj));
                } else {
                    throw new RuntimeException("The current key type does not support PEM encoding");
                }
            }

            // 处理获取对应密钥类型的 ASN1 结构的 byte[]
            byte[] keyBytes;
            if (keyType == KeyType.PRIVATE_KEY_PKCS8) {
                // PKCS#8 PrivateKey
                keyBytes = encodeObj.getEncoded();
            } else if (keyType == KeyType.PUBLIC_KEY_X509) {
                keyBytes = encodeObj.getEncoded();
            } else if (keyType == KeyType.PRIVATE_KEY_PKCS1_RSA || keyType == KeyType.PRIVATE_KEY_SEC1_EC) {
                // PKCS#1 or SEC1 PrivateKey
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encodeObj);
                keyBytes = privateKeyInfo.parsePrivateKey().toASN1Primitive().getEncoded();
            } else if (keyType == KeyType.PRIVATE_KEY_PLAIN_SM2) {
                // SM2 Plain PrivateKey
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encodeObj);
                PrivateKey privateKey = new KeyFactorySpi.EC().generatePrivate(privateKeyInfo);
                keyBytes = SM2.getSwapPrivateKey(privateKey);
            } else if (keyType == KeyType.PUBLIC_KEY_PLAIN_SM2) {
                // SM2 Plain PublicKey
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(encodeObj);
                PublicKey publicKey = new KeyFactorySpi.EC().generatePublic(publicKeyInfo);
                keyBytes = SM2.getSwapPublicKey(publicKey);
            } else {
                throw new RuntimeException("unsupported key type: " + keyType);
            }

            if (encoding == TextEncoding.HEX) {
                return TextCodec.HEX.getEncodeFunc().apply(keyBytes);
            } else {
                // 默认输出 Base64 编码
                return TextCodec.BASE64.getEncodeFunc().apply(keyBytes);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
