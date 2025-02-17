package com.changhr.utils.crypto.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 密钥生成和还原的工具类
 *
 * @author changhr2013
 */
public class KeyUtil {

    private KeyUtil() {
    }

    /**
     * 生成私钥，仅用于非对称加密<br>
     * 采用 PKCS#8 规范，此规范定义了私钥信息语法和加密私钥语法<br>
     * 算法见：<a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyFactory">KeyFactory</a>
     *
     * @param algorithm 算法，RSA | SM2 | ECDSA
     * @param key       密钥，PKCS#8 格式
     * @return 私钥 {@link PrivateKey}
     */
    public static PrivateKey generatePrivateKey(String algorithm, byte[] key) {
        if (null == key) {
            return null;
        }
        return generatePrivateKey(algorithm, new PKCS8EncodedKeySpec(key));
    }

    /**
     * 生成私钥，格式为 Open SSL 生成的 pem object
     *
     * @param algorithm 算法，RSA | SM2 | ECDSA
     * @param key       密钥，Open SSL pem 格式
     * @return 私钥 {@link PrivateKey}
     */
    public static PrivateKey generatePrivateKeyFromOpenSSL(String algorithm, byte[] key) {
        if (null == key) {
            return null;
        }
        try {
            // 不使用 jce provider，因此特殊处理 SM2
            if ("SM2".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC ecKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC();
                AlgorithmIdentifier sm2Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, GMObjectIdentifiers.sm2p256v1);
                ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(key);
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(sm2Identifier, ecPrivateKey);
                return ecKeyFactory.generatePrivate(privateKeyInfo);
            } else if ("RSA".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi rsaKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi();
                AlgorithmIdentifier rsaIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
                RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(key);
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(rsaIdentifier, rsaPrivateKey);
                return rsaKeyFactory.generatePrivate(privateKeyInfo);
            } else if ("ECDSA".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECDSA ecKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECDSA();
                AlgorithmIdentifier ecdsaIdentifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256k1);
                ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(key);
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(ecdsaIdentifier, ecPrivateKey);
                return ecKeyFactory.generatePrivate(privateKeyInfo);
            } else {
                throw new IllegalArgumentException("unsupported algorithm: " + algorithm);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 检查是否为 PKCS#8 格式的私钥
     *
     * @param asn1Encoding asn1 字节数组
     * @return 如果是 PKCS#8 格式返回 true，否则返回 false
     */
    public static boolean checkIsPkcs8PrivateKeyInfo(byte[] asn1Encoding) {
        try {
            // 判断规则，当序列化后的结构第一个参数为 ASN1Integer，第二个参数为 AlgorithmIdentifier 或 ASN1Sequence 时
            // 就认为当前结构符合 PKCS#8 结构，按 PKCS#8 结构进行处理
            ASN1Sequence seq = ASN1Sequence.getInstance(asn1Encoding);

            // version
            ASN1Encodable version = seq.getObjectAt(0);
            if (!(version instanceof ASN1Integer)) {
                return false;
            }

            // algorithm
            ASN1Encodable algorithm = seq.getObjectAt(1);
            if (algorithm instanceof AlgorithmIdentifier) {
                return true;
            }

            // 如果为 sequence，判断内部第一个参数是否为 ASN1ObjectIdentifier
            if (algorithm instanceof ASN1Sequence) {
                ASN1Sequence algoSeq = ASN1Sequence.getInstance(algorithm);
                if (algoSeq.getObjectAt(0) instanceof ASN1ObjectIdentifier) {
                    return true;
                } else {
                    return false;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 生成私钥，仅用于非对称加密<br>
     * 算法见：<a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyFactory">KeyFactory</a>
     *
     * @param algorithm 算法，如 RSA、SM2、ECDSA 等
     * @param keySpec   密钥，PKCS#8 {@link PKCS8EncodedKeySpec} 格式，兼容 PKCS#1 和 SEC1 格式 {@link KeySpec}
     * @return 私钥 {@link PrivateKey}
     */
    public static PrivateKey generatePrivateKey(String algorithm, KeySpec keySpec) {
        if (null == keySpec) {
            return null;
        }

        byte[] asn1Encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

        // 检查如果不是 PKCS#8 格式，尝试使用 PKCS#1/SEC1 格式解析
        if (!checkIsPkcs8PrivateKeyInfo(asn1Encoded)) {
            return generatePrivateKeyFromOpenSSL(algorithm, asn1Encoded);
        }

        try {
            // 不使用 jce provider，因此特殊处理 SM2
            if ("SM2".equalsIgnoreCase(algorithm) || "EC".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC ecKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC();
                return ecKeyFactory.generatePrivate(PrivateKeyInfo.getInstance(asn1Encoded));
            } else if ("ECDSA".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECDSA ecKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECDSA();
                return ecKeyFactory.generatePrivate(PrivateKeyInfo.getInstance(asn1Encoded));
            } else if ("RSA".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi rsaKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi();
                return rsaKeyFactory.generatePrivate(PrivateKeyInfo.getInstance(asn1Encoded));
            } else {
                // 没有匹配到的密钥类型使用 JCE 处理
                algorithm = getAlgorithmAfterWith(algorithm);
                return getKeyFactory(algorithm).generatePrivate(keySpec);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 生成公钥，仅用于非对称加密<br>
     * 采用 X509 证书规范<br>
     * 算法见：<a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyFactory">KeyFactory</a>
     *
     * @param algorithm 算法
     * @param key       密钥，必须为 DER 编码存储
     * @return 公钥 {@link PublicKey}
     */
    public static PublicKey generatePublicKey(String algorithm, byte[] key) {
        if (null == key) {
            return null;
        }
        return generatePublicKey(algorithm, new X509EncodedKeySpec(key));
    }

    /**
     * 生成公钥，仅用于非对称加密<br>
     * 算法见：<a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyFactory">KeyFactory</a>
     *
     * @param algorithm 算法
     * @param keySpec   {@link KeySpec}
     * @return 公钥 {@link PublicKey}
     */
    public static PublicKey generatePublicKey(String algorithm, KeySpec keySpec) {
        if (null == keySpec) {
            return null;
        }

        byte[] asn1Encoded = ((X509EncodedKeySpec) keySpec).getEncoded();

        try {
            // 不使用 jce provider，因此特殊处理 SM2
            if ("SM2".equalsIgnoreCase(algorithm) || "EC".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC ecKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC();
                return ecKeyFactory.generatePublic(SubjectPublicKeyInfo.getInstance(asn1Encoded));
            } else if ("ECDSA".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECDSA ecKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.ECDSA();
                return ecKeyFactory.generatePublic(SubjectPublicKeyInfo.getInstance(asn1Encoded));
            } else if ("RSA".equalsIgnoreCase(algorithm)) {
                org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi rsaKeyFactory = new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi();
                return rsaKeyFactory.generatePublic(SubjectPublicKeyInfo.getInstance(asn1Encoded));
            } else {
                // 没有匹配到的密钥类型使用 JCE 处理
                algorithm = getAlgorithmAfterWith(algorithm);
                return getKeyFactory(algorithm).generatePublic(keySpec);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取{@link KeyFactory}
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyFactory}
     */
    public static KeyFactory getKeyFactory(String algorithm) {
        //        final Provider provider = GlobalBouncyCastleProvider.INSTANCE.getProvider();

        final Provider provider = null;
        KeyFactory keyFactory;
        try {
            keyFactory = (null == provider)
                    ? KeyFactory.getInstance(getMainAlgorithm(algorithm))
                    : KeyFactory.getInstance(getMainAlgorithm(algorithm), provider);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return keyFactory;
    }

    /**
     * 获取主体算法名，例如 RSA/ECB/PKCS1Padding 的主体算法是 RSA
     *
     * @param algorithm XXXwithXXX 算法
     * @return 主体算法名
     */
    public static String getMainAlgorithm(String algorithm) {
        if (algorithm == null) {
            throw new RuntimeException("Algorithm must be not blank!");
        }
        final int slashIndex = algorithm.indexOf("/");
        if (slashIndex > 0) {
            return algorithm.substring(0, slashIndex);
        }
        return algorithm;
    }

    /**
     * 获取用于密钥生成的算法<br>
     * 获取 XXXwithXXX 算法的后半部分算法，如果为 ECDSA 或 SM2，返回算法为 EC
     *
     * @param algorithm XXXwithXXX 算法
     * @return 算法
     */
    public static String getAlgorithmAfterWith(String algorithm) {

        if (algorithm == null) {
            throw new RuntimeException("algorithm must be not null !");
        }

        if (StrUtil.startWithIgnoreCase(algorithm, "ECIESWith")) {
            return "EC";
        }

        int indexOfWith = StrUtil.lastIndexOfIgnoreCase(algorithm, "with");
        if (indexOfWith > 0) {
            algorithm = StrUtil.subSuf(algorithm, indexOfWith + "with".length());
        }
        if ("ECDSA".equalsIgnoreCase(algorithm)
                || "SM2".equalsIgnoreCase(algorithm)
                || "ECIES".equalsIgnoreCase(algorithm)
        ) {
            algorithm = "EC";
        }
        return algorithm;
    }

    /**
     * 从公钥信息中获取公钥
     *
     * @param subjectPublicKeyInfo 公钥信息
     * @return 公钥
     */
    public static PublicKey getPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws Exception {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        bouncyCastleProvider.addKeyInfoConverter(PKCSObjectIdentifiers.rsaEncryption, new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi());
        bouncyCastleProvider.addKeyInfoConverter(X9ObjectIdentifiers.id_ecPublicKey, new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
        return BouncyCastleProvider.getPublicKey(subjectPublicKeyInfo);
    }
}
