package com.changhr.utils.crypto.asymmetric;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.*;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * 基于 Bouncy Castle 封装的国密 SM2 非对称加/解密算法工具类 <br/>
 * BC 库 SM2 算法签名/验签使用 DER 编码；加密/解密使用 c1||c2||c3 旧标准，不使用 DER 编码
 * </p>
 * <p>
 * 此工具类：<br/>
 * encrypt/decrypt: 使用 c1||c3||c2 新标准，不使用 DER 编码 <br/>
 * encryptWithDER/decryptWithDER: 使用 c1||c3||c2 新标准，使用 DER 编码
 * </p>
 * <p>
 * encryptOld/decryptOld: 使用 c1||c2||c3 旧标准，不使用 DER 编码 <br/>
 * encryptOldWithDER/decryptOldWithDER: 使用 c1||c2||c3 旧标准，使用 DER 编码
 * </p>
 * <p>
 * sign/verify: 签名/验签方法不使用 DER 编码 <br/>
 * signWithAsn1/verifyWithAsn1: 签名/验签方法使用 DER 编码
 * </p>
 *
 * @author changhr2013
 */
public abstract class SM2 {

    /**
     * 密钥算法类型
     */
    public static final String KEY_ALGORITHM = "EC";

    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "SM3withSM2";

    /**
     * KeyMap 中公钥索引 KEY
     */
    private static final String PUBLIC_KEY = "SM2PublicKey";

    /**
     * KeyMap 中私钥索引 KEY
     */
    private static final String PRIVATE_KEY = "SM2PrivateKey";

    /**
     * SM2 标准曲线名称
     */
    public static final String SM2_CURVE_NAME = "sm2p256v1";

    /**
     * SM2 标准曲线
     */
    private static final X9ECParameters X9_EC_PARAMETERS = GMNamedCurves.getByName(SM2_CURVE_NAME);

    /**
     * SM2 标准杂凑值
     */
    public static final byte[] USER_ID = "1234567812345678".getBytes();

    private static final int RS_LEN = 32;

    private static final ECDomainParameters EC_DOMAIN_PARAMETERS = new ECNamedDomainParameters(GMNamedCurves.getOID(SM2_CURVE_NAME), X9_EC_PARAMETERS.getCurve(), X9_EC_PARAMETERS.getG(), X9_EC_PARAMETERS.getN(), X9_EC_PARAMETERS.getH());

    private static final ECParameterSpec EC_PARAMETER_SPEC = new ECNamedCurveParameterSpec(SM2_CURVE_NAME, X9_EC_PARAMETERS.getCurve(), X9_EC_PARAMETERS.getG(), X9_EC_PARAMETERS.getN(), X9_EC_PARAMETERS.getH());

    /**
     * 使用私钥对数据签名，结果为直接拼接 rs 的字节数组
     *
     * @param msg            待签名数据
     * @param swapPrivateKey SM2 交换私钥
     * @return r||s，直接拼接 byte 数组的 rs
     */
    public static byte[] sign(byte[] msg, byte[] swapPrivateKey) {
        return sign(msg, USER_ID, swapPrivateKey);
    }

    /**
     * 使用私钥对数据签名，结果为直接拼接 rs 的字节数组
     *
     * @param msg            待签名数据
     * @param userId         签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param swapPrivateKey SM2 交换私钥
     * @return r||s，直接拼接 byte 数组的 rs
     */
    public static byte[] sign(byte[] msg, byte[] userId, byte[] swapPrivateKey) {
        return rsAsn1ToPlainByteArray(signWithAsn1(msg, userId, swapPrivateKey));
    }

    /**
     * 使用私钥对数据签名，结果为 ASN1 格式的 rs 的字节数组
     *
     * @param msg            待签名数据
     * @param swapPrivateKey SM2 交换私钥
     * @return rs in <b>asn1 format</b>
     */
    public static byte[] signWithAsn1(byte[] msg, byte[] swapPrivateKey) {
        return signWithAsn1(msg, USER_ID, swapPrivateKey);
    }

    /**
     * 使用私钥对数据签名，结果为 ASN1 格式的 rs 的字节数组
     *
     * @param msg            待签名数据
     * @param userId         签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param swapPrivateKey SM2 交换私钥
     * @return rs in <b>asn1 format</b>
     */
    public static byte[] signWithAsn1(byte[] msg, byte[] userId, byte[] swapPrivateKey) {
        BCECPrivateKey bcecPrivateKey = buildPrivateKey(swapPrivateKey);
        return signWithAsn1(msg, userId, bcecPrivateKey);
    }

    /**
     * 使用私钥对数据签名，结果为 ASN1 格式的 rs 的字节数组
     *
     * @param msg        待签名数据
     * @param userId     签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param privateKey SM2 BCECPrivateKey
     * @return rs in <b>asn1 format</b>
     */
    public static byte[] signWithAsn1(byte[] msg, byte[] userId, PrivateKey privateKey) {
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), EC_DOMAIN_PARAMETERS);
        ParametersWithID sm2Parameters = new ParametersWithID(ecPrivateKeyParameters, userId);
        try {
            SM2Signer sm2Signer = new SM2Signer();
            sm2Signer.init(true, sm2Parameters);

            sm2Signer.update(msg, 0, msg.length);
            return sm2Signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 验证直接拼接 rs 的签名
     *
     * @param msg           待验签的数据
     * @param userId        签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param swapPublicKey SM2 交换公钥
     * @param rs            r||s，直接拼接 byte 数组的 rs
     * @return boolean
     */
    public static boolean verify(byte[] msg, byte[] userId, byte[] swapPublicKey, byte[] rs) {
        return verifyWithAsn1(msg, userId, swapPublicKey, rsPlainByteArrayToAsn1(rs));
    }

    /**
     * 验证直接拼接 rs 的签名
     *
     * @param msg           待验签的数据
     * @param swapPublicKey SM2 交换公钥
     * @param rs            r||s，直接拼接 byte 数组的 rs
     * @return boolean
     */
    public static boolean verify(byte[] msg, byte[] swapPublicKey, byte[] rs) {
        return verify(msg, USER_ID, swapPublicKey, rs);
    }

    /**
     * 验证 ASN1 格式的签名
     *
     * @param msg           待验签的数据
     * @param userId        签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param swapPublicKey SM2 交换公钥
     * @param rs            in <b>asn1 format<b/>
     * @return boolean
     */
    public static boolean verifyWithAsn1(byte[] msg, byte[] userId, byte[] swapPublicKey, byte[] rs) {
        BCECPublicKey bcecPublicKey = buildPublicKey(swapPublicKey);
        return verifyWithAsn1(msg, userId, bcecPublicKey, rs);
    }

    /**
     * 验证 ASN1 格式的签名
     *
     * @param msg       待验签的数据
     * @param userId    签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param publicKey SM2 公钥
     * @param rs        in <b>asn1 format<b/>
     * @return boolean
     */
    public static boolean verifyWithAsn1(byte[] msg, byte[] userId, PublicKey publicKey, byte[] rs) {
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), EC_DOMAIN_PARAMETERS);
        ParametersWithID sm2Parameters = new ParametersWithID(ecPublicKeyParameters, userId);
        try {
            SM2Signer sm2Signer = new SM2Signer();
            sm2Signer.init(false, sm2Parameters);
            sm2Signer.update(msg, 0, msg.length);
            return sm2Signer.verifySignature(rs);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 验证 ASN1 格式的签名
     *
     * @param msg           待验签的数据
     * @param swapPublicKey SM2 交换公钥
     * @param rs            in <b>asn1 format<b/>
     * @return boolean
     */
    public static boolean verifyWithAsn1(byte[] msg, byte[] swapPublicKey, byte[] rs) {
        return verifyWithAsn1(msg, USER_ID, swapPublicKey, rs);
    }

    /**
     * BC 的 SM3withSM2 签名得到的结果的 rs 是 asn1 格式的，这个方法转换成直接拼接的 r||s
     *
     * @param rsDer rs in asn1 format
     * @return sign result in plain byte array
     */
    public static byte[] rsAsn1ToPlainByteArray(byte[] rsDer) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(rsDer);
        byte[] r = bigIntToFixedLengthBytes(ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue());
        byte[] s = bigIntToFixedLengthBytes(ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue());
        byte[] result = new byte[RS_LEN * 2];
        System.arraycopy(r, 0, result, 0, r.length);
        System.arraycopy(s, 0, result, RS_LEN, s.length);
        return result;
    }

    /**
     * 将 BigInteger 转换为定长的字节数组
     *
     * @param rOrS BigInteger
     * @return byte[] 定长的字节数组，长度为 32(RS_LEN)
     */
    private static byte[] bigIntToFixedLengthBytes(BigInteger rOrS) {
        // for sm2p256v1, n is 00fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
        // n and s are the result of mod n, so they should be less than n and have length < 32.
        byte[] rs = rOrS.toByteArray();
        if (rs.length == RS_LEN) {
            return rs;
        } else if (rs.length == RS_LEN + 1 && rs[0] == 0) {
            return Arrays.copyOfRange(rs, 1, RS_LEN + 1);
        } else if (rs.length < RS_LEN) {
            byte[] result = new byte[RS_LEN];
            Arrays.fill(result, (byte) 0);
            System.arraycopy(rs, 0, result, RS_LEN - rs.length, rs.length);
            return result;
        } else {
            throw new RuntimeException("error rs: " + Hex.toHexString(rs));
        }
    }

    /**
     * BC 的 SM3withSM2 验签需要的 rs 是 asn1 格式的，这个方法将直接拼接 r||s 的字节数组转化成 asn1 格式
     *
     * @param sign in plain byte array
     * @return rs result in asn1 format
     */
    public static byte[] rsPlainByteArrayToAsn1(byte[] sign) {
        if (sign.length != RS_LEN * 2) {
            throw new RuntimeException("error rs.");
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称公钥加密
     *
     * @param data          待加密数据
     * @param swapPublicKey SM2 交换公钥
     * @return byte[]
     */
    public static byte[] encryptOld(byte[] data, byte[] swapPublicKey) {
        BCECPublicKey bcecPublicKey = buildPublicKey(swapPublicKey);
        return encryptOld(data, bcecPublicKey);
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称公钥加密
     *
     * @param data      待加密数据
     * @param publicKey SM2 公钥
     * @return byte[]
     */
    public static byte[] encryptOld(byte[] data, PublicKey publicKey) {
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), EC_DOMAIN_PARAMETERS);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, CryptoServicesRegistrar.getSecureRandom()));
        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称公钥加密
     * 加密结果使用 DER 编码
     *
     * @param data          待加密数据
     * @param swapPublicKey SM2 交换公钥
     * @return byte[]
     */
    public static byte[] encryptOldWithDER(byte[] data, byte[] swapPublicKey) {
        return encodeAsn1Cipher(encryptOld(data, swapPublicKey), SM2Engine.Mode.C1C2C3);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称公钥加密
     *
     * @param data          待加密数据
     * @param swapPublicKey SM2 交换公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] data, byte[] swapPublicKey) {
        BCECPublicKey bcecPublicKey = buildPublicKey(swapPublicKey);
        return encrypt(data, bcecPublicKey);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称公钥加密
     *
     * @param data      待加密数据
     * @param publicKey SM2 公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey) {
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), EC_DOMAIN_PARAMETERS);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, CryptoServicesRegistrar.getSecureRandom()));
        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称公钥加密
     * 加密结果使用 DER 编码
     *
     * @param data          待加密数据
     * @param swapPublicKey SM2 交换公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encryptWithDER(byte[] data, byte[] swapPublicKey) {
        return encodeAsn1Cipher(encrypt(data, swapPublicKey), SM2Engine.Mode.C1C3C2);
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称私钥解密
     *
     * @param data           密文
     * @param swapPrivateKey SM2 交换私钥
     * @return byte[] 解密后的数据
     */
    public static byte[] decryptOld(byte[] data, byte[] swapPrivateKey) {
        BCECPrivateKey bcecPrivateKey = buildPrivateKey(swapPrivateKey);
        return decryptOld(data, bcecPrivateKey);
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称私钥解密
     *
     * @param data       密文
     * @param privateKey SM2 私钥
     * @return byte[] 解密后的数据
     */
    public static byte[] decryptOld(byte[] data, PrivateKey privateKey) {
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
        byte[] c1c2c3 = convertDataToUnCompressed(data);
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), EC_DOMAIN_PARAMETERS);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);
        try {
            return sm2Engine.processBlock(c1c2c3, 0, c1c2c3.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称私钥解密
     * 密文使用 DER 编码
     *
     * @param data           待解密数据
     * @param swapPrivateKey SM2 交换私钥
     * @return byte[] 解密后的数据
     */
    public static byte[] decryptOldWithDER(byte[] data, byte[] swapPrivateKey) {
        return decryptOld(decodeAsn1Cipher(data, SM2Engine.Mode.C1C2C3), swapPrivateKey);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称私钥解密
     *
     * @param data           密文
     * @param swapPrivateKey SM2 交换私钥
     * @return byte[]
     */
    public static byte[] decrypt(byte[] data, byte[] swapPrivateKey) {
        BCECPrivateKey bcecPrivateKey = buildPrivateKey(swapPrivateKey);
        return decrypt(data, bcecPrivateKey);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称私钥解密
     *
     * @param data       密文
     * @param privateKey SM2 私钥
     * @return byte[]
     */
    public static byte[] decrypt(byte[] data, PrivateKey privateKey) {
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
        byte[] c1c2c3 = convertDataToUnCompressed(data);
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), EC_DOMAIN_PARAMETERS);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(false, ecPrivateKeyParameters);
        try {
            return sm2Engine.processBlock(c1c2c3, 0, c1c2c3.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称私钥解密
     * 密文使用 DER 编码
     *
     * @param data           密文
     * @param swapPrivateKey SM2 交换私钥
     * @return byte[]
     */
    public static byte[] decryptWithDER(byte[] data, byte[] swapPrivateKey) {
        return decrypt(decodeAsn1Cipher(data, SM2Engine.Mode.C1C3C2), swapPrivateKey);
    }

    /**
     * BC 库解密时密文中的 c1 要求为非压缩格式
     * 此方法判断密文中的 c1 是否压缩，如果压缩就转换为未压缩的再给 BC 库解密
     *
     * @param data 公钥加密的密文
     * @return 未压缩 c1 的密文
     */
    public static byte[] convertDataToUnCompressed(byte[] data) {
        ECPoint p;
        int expectedLength = (X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8;
        byte type = data[0];
        byte[] c1;

        switch (type) {
            // infinity
            case 0x00: {
                p = X9_EC_PARAMETERS.getCurve().getInfinity();
                c1 = new byte[1];
                System.arraycopy(data, 0, c1, 0, c1.length);
                break;
            }
            // compressed
            case 0x02:
            case 0x03: {
                c1 = new byte[expectedLength + 1];
                System.arraycopy(data, 0, c1, 0, c1.length);
                p = X9_EC_PARAMETERS.getCurve().decodePoint(c1);
                break;
            }
            // uncompressed
            case 0x04: {
                return data;
            }
            // hybrid
            case 0x06:
            case 0x07: {
                c1 = new byte[2 * expectedLength + 1];
                System.arraycopy(data, 0, c1, 0, c1.length);
                p = X9_EC_PARAMETERS.getCurve().decodePoint(c1);
                break;
            }
            default:
                throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(type, 16));
        }

        byte[] completeC1 = p.getEncoded(false);

        byte[] result = new byte[completeC1.length + data.length - c1.length];
        System.arraycopy(completeC1, 0, result, 0, completeC1.length);
        System.arraycopy(data, c1.length, result, completeC1.length, data.length - c1.length);
        return result;
    }

    /**
     * BC 加解密使用旧标 c1||c2||c3，此方法在加密后调用，将结果转换为 c1||c3||c2
     *
     * @param c1c2c3 c1c2c3 拼接顺序的 byte 数组
     * @return byte[] c1c3c2
     */
    public static byte[] changeC1C2C3ToC1C3C2(byte[] c1c2c3) {
        // sm2p256v1 的这个固定 65。可以看 GMNamedCurves、ECCurve 代码
        final int c1Len = (X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        // 长度为 new SM3Digest().getDigestSize()
        final int c3Len = 32;
        byte[] result = new byte[c1c2c3.length];
        // c1
        System.arraycopy(c1c2c3, 0, result, 0, c1Len);
        // c3
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, result, c1Len, c3Len);
        // c2
        System.arraycopy(c1c2c3, c1Len, result, c1Len + c3Len, c1c2c3.length - c1Len - c3Len);
        return result;
    }

    /**
     * BC 加解密使用旧标 c1||c2||c3，此方法在解密前调用，将密文转换为 c1||c2||c3 再去解密
     *
     * @param c1c3c2 c1c3c2 拼接的 byte 数组
     * @return byte[] c1c2c3
     */
    public static byte[] changeC1C3C2ToC1C2C3(byte[] c1c3c2) {
        // sm2p256v1 的这个固定 65。可以看 GMNamedCurves、ECCurve 代码
        final int c1Len = (X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        // 长度为 new SM3Digest().getDigestSize()
        final int c3Len = 32;
        byte[] result = new byte[c1c3c2.length];
        // c1
        System.arraycopy(c1c3c2, 0, result, 0, c1Len);
        // c2
        System.arraycopy(c1c3c2, c1Len + c3Len, result, c1Len, c1c3c2.length - c1Len - c3Len);
        // c3
        System.arraycopy(c1c3c2, c1Len, result, c1c3c2.length - c3Len, c3Len);
        return result;
    }

    /**
     * 为原始密文添加 ASN1 编码
     *
     * @param plainCipher 原始密文
     * @return ASN1 编码的格式的密文
     */
    public static byte[] encodeAsn1Cipher(byte[] plainCipher, SM2Engine.Mode mode) {
        // sm2p256v1 的这个固定 65。可以看 GMNamedCurves、ECCurve 代码
        final int c1Len = (X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        byte[] c1 = new byte[c1Len];
        System.arraycopy(plainCipher, 0, c1, 0, c1Len);

        BigInteger x = X9_EC_PARAMETERS.getCurve().decodePoint(c1).getXCoord().toBigInteger();
        BigInteger y = X9_EC_PARAMETERS.getCurve().decodePoint(c1).getYCoord().toBigInteger();

        // 长度为 new SM3Digest().getDigestSize()
        final int c3Len = 32;
        byte[] c3 = new byte[c3Len];

        final int c2Len = plainCipher.length - c1Len - c3Len;
        byte[] c2 = new byte[c2Len];

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(x));
        v.add(new ASN1Integer(y));

        if (mode == SM2Engine.Mode.C1C3C2) {
            System.arraycopy(plainCipher, c1.length, c3, 0, c3Len);
            System.arraycopy(plainCipher, c1Len + c3Len, c2, 0, c2Len);
            v.add(new DEROctetString(c3));
            v.add(new DEROctetString(c2));
        } else {
            System.arraycopy(plainCipher, plainCipher.length - c3Len, c3, 0, c3Len);
            System.arraycopy(plainCipher, c1Len, c2, 0, c2Len);
            v.add(new DEROctetString(c2));
            v.add(new DEROctetString(c3));
        }
        try {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 解码 ASN1 编码的密文
     *
     * @param asn1Cipher DER 编码的密文
     * @return 原始密文
     */
    public static byte[] decodeAsn1Cipher(byte[] asn1Cipher, SM2Engine.Mode mode) {
        ASN1Sequence sequence;
        try {
            sequence = (ASN1Sequence) DERSequence.fromByteArray(asn1Cipher);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        BigInteger x = ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue();
        BigInteger y = ASN1Integer.getInstance(sequence.getObjectAt(1)).getPositiveValue();
        byte[] c1 = X9_EC_PARAMETERS.getCurve().validatePoint(x, y).getEncoded(false);

        byte[] c2, c3;
        if (mode == SM2Engine.Mode.C1C3C2) {
            c3 = ((ASN1OctetString) sequence.getObjectAt(2)).getOctets();
            c2 = ((ASN1OctetString) sequence.getObjectAt(3)).getOctets();
        } else {
            c2 = ((ASN1OctetString) sequence.getObjectAt(2)).getOctets();
            c3 = ((ASN1OctetString) sequence.getObjectAt(3)).getOctets();
        }

        byte[] plainCipher = new byte[c1.length + c2.length + c3.length];
        System.arraycopy(c1, 0, plainCipher, 0, c1.length);
        if (mode == SM2Engine.Mode.C1C3C2) {
            System.arraycopy(c3, 0, plainCipher, c1.length, c3.length);
            System.arraycopy(c2, 0, plainCipher, c1.length + c3.length, c2.length);
        } else {
            System.arraycopy(c2, 0, plainCipher, c1.length, c2.length);
            System.arraycopy(c3, 0, plainCipher, c1.length + c2.length, c3.length);
        }
        return plainCipher;
    }

    /**
     * 生成 SM2 密钥对
     *
     * @return KeyMap 密钥对
     */
    public static KeyPair initKeyPair() {
        try {
            // 实例化密钥对生成器
            KeyPairGeneratorSpi.EC ecKeyPairGen = new KeyPairGeneratorSpi.EC(KEY_ALGORITHM, BouncyCastleProvider.CONFIGURATION);
            ecKeyPairGen.initialize(EC_PARAMETER_SPEC, new SecureRandom());
            return ecKeyPairGen.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException("invalid algorithm parameter exception", e);
        }
    }

    /**
     * 初始化密钥 KeyMap
     *
     * @return Map 密钥 Map
     */
    public static Map<String, Object> initKey() {
        // 生成密钥对
        KeyPair keyPair = initKeyPair();
        // 公钥
        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        // 私钥
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        // 封装密钥
        Map<String, Object> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * 获取私钥分量 D 作为交换的私钥（32 个字节）
     *
     * @param keyMap 密钥 Map
     * @return byte[] SM2 交换私钥（私钥分量 D 的字节数组）
     */
    public static byte[] getSwapPrivateKey(Map<String, Object> keyMap) {
        BCECPrivateKey privateKey = (BCECPrivateKey) keyMap.get(PRIVATE_KEY);
        return bigIntToFixedLengthBytes(privateKey.getD());
    }

    /**
     * 通过 SM2 私钥计算公钥值
     *
     * @param privateKeyBytes 私钥字节数组
     * @param compressed      公钥是否压缩
     * @return 公钥字节数组
     */
    public static byte[] computePublicKey(byte[] privateKeyBytes, boolean compressed) {
        ECPoint Q = new FixedPointCombMultiplier().multiply(X9_EC_PARAMETERS.getG(), new BigInteger(1, privateKeyBytes));
        return EC_DOMAIN_PARAMETERS.validatePublicPoint(Q).getEncoded(compressed);
    }

    /**
     * 获取公钥分量 X，Y 作为交换的公钥（65 个字节）
     * 默认不压缩公钥
     *
     * @param keyMap 密钥 Map
     * @return SM2 交换公钥（公钥分量 X，Y 拼合的字节数组）
     */
    public static byte[] getSwapPublicKey(Map<String, Object> keyMap) {
        return getSwapPublicKey(keyMap, false);
    }

    /**
     * 获取公钥分量 X，Y 作为交换的公钥（65 个字节或 33 个字节）
     *
     * @param keyMap     密钥 Map
     * @param compressed 公钥是否进行压缩
     * @return byte[] SM2 交换公钥（公钥分量 X，Y 拼合的字节数组）
     */
    public static byte[] getSwapPublicKey(Map<String, Object> keyMap, boolean compressed) {
        BCECPublicKey publicKey = (BCECPublicKey) keyMap.get(PUBLIC_KEY);
        return publicKey.getQ().getEncoded(compressed);
    }

    /**
     * 从证书获取公钥
     *
     * @param file X509 文件
     * @return 公钥
     */
    public static PublicKey getPublicKeyFromX509File(File file) {
        try {
            try (FileInputStream in = new FileInputStream(file)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);
                return certificate.getPublicKey();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 从交换私钥还原完整的 BCECPrivateKey
     *
     * @param swapPrivateKey 交换私钥（D 分量字节数组）
     * @return BCECPrivateKey 完整的私钥
     */
    public static BCECPrivateKey buildPrivateKey(byte[] swapPrivateKey) {
        // 私钥参数
        BigInteger d = new BigInteger(1, swapPrivateKey);
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(d, EC_DOMAIN_PARAMETERS);
        // 计算公钥
        byte[] swapPublicKey = computePublicKey(swapPrivateKey, false);
        BCECPublicKey bcecPublicKey = buildPublicKey(swapPublicKey);
        // 构建 BCECPrivateKey
        return new BCECPrivateKey(KEY_ALGORITHM, ecPrivateKeyParameters, bcecPublicKey, EC_PARAMETER_SPEC, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 从交换公钥的字节数组中还原出 BCECPublicKey
     *
     * @param swapPublicKey 交换公钥的字节数组（标志位 + 点）
     * @return BCECPublicKey 完整的公钥
     */
    public static BCECPublicKey buildPublicKey(byte[] swapPublicKey) {
        ECPoint ecPoint = X9_EC_PARAMETERS.getCurve().decodePoint(swapPublicKey);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, EC_PARAMETER_SPEC);
        return new BCECPublicKey(KEY_ALGORITHM, ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 从 BCECPrivateKey 获取 D 分量字节数组
     *
     * @param privateKey BCECPrivateKey
     * @return byte[]，D 分量字节数组
     */
    public static byte[] getSwapPrivateKey(PrivateKey privateKey) {
        return BigIntegers.asUnsignedByteArray(RS_LEN, ((BCECPrivateKey) privateKey).getD());
    }

    /**
     * 从 BCECPublicKey 获取 Q 点字节数组，公钥默认非压缩
     *
     * @param publicKey BCECPublicKey
     * @return byte[]，标志位 + 公钥点坐标
     */
    public static byte[] getSwapPublicKey(PublicKey publicKey) {
        return getSwapPublicKey(publicKey, false);
    }

    /**
     * 从 BCECPublicKey 获取 Q 点字节数组
     *
     * @param publicKey  BCECPublicKey
     * @param compressed 公钥是否压缩
     * @return byte[]，标志位 + 公钥点坐标
     */
    public static byte[] getSwapPublicKey(PublicKey publicKey, boolean compressed) {
        return ((BCECPublicKey) publicKey).getQ().getEncoded(compressed);
    }

    /**
     * 通过私钥生成预处理数据
     *
     * @param inData         原始输入数据
     * @param swapPrivateKey 交换私钥（D 分量字节数组）
     * @return 预处理后的输入数据
     */
    public static byte[] getEHashByPrivateKey(byte[] inData, byte[] swapPrivateKey) {
        return getEHashByPrivateKey(inData, swapPrivateKey, USER_ID);
    }

    /**
     * 通过私钥生成预处理数据
     *
     * @param inData         原始输入数据
     * @param swapPrivateKey 交换私钥（D 分量字节数组）
     * @param userId         签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @return 预处理后的输入数据
     */
    public static byte[] getEHashByPrivateKey(byte[] inData, byte[] swapPrivateKey, byte[] userId) {
        BCECPrivateKey privateKey = buildPrivateKey(swapPrivateKey);
        AsymmetricKeyParameter ecParam;
        try {
            ecParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("PrivateKeyFactory create private key failed", e);
        }
        return getEHash(true, new ParametersWithID(ecParam, userId), inData);
    }

    /**
     * 通过公钥生成预处理数据
     *
     * @param inData        交换公钥的字节数组（标志位 + 点）
     * @param swapPublicKey 公钥原始值
     * @return 预处理后的输入数据
     */
    public static byte[] getEHashByPublicKey(byte[] inData, byte[] swapPublicKey) {
        return getEHashByPublicKey(inData, swapPublicKey, USER_ID);
    }

    /**
     * 通过公钥生成预处理数据
     *
     * @param inData        交换公钥的字节数组（标志位 + 点）
     * @param swapPublicKey 公钥原始值
     * @param userId        签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @return 预处理后的输入数据
     */
    public static byte[] getEHashByPublicKey(byte[] inData, byte[] swapPublicKey, byte[] userId) {
        BCECPublicKey publicKey = buildPublicKey(swapPublicKey);

        AsymmetricKeyParameter ecParam;
        try {
            ecParam = ECUtil.generatePublicKeyParameter(publicKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("ECUtil generate public key failed");
        }
        return getEHash(false, new ParametersWithID(ecParam, userId), inData);
    }

    /**
     * SM2 预处理生成 eHash
     *
     * @param forSigning 是否是签名操作
     * @param param      公钥 or 私钥
     * @return 预处理的前缀参数
     */
    private static byte[] getEHash(boolean forSigning, CipherParameters param, byte[] inData) {

        ECPoint pubPoint;
        ECKeyParameters ecKey;
        ECDomainParameters ecParams;

        CipherParameters baseParam;
        byte[] userID;

        if (param instanceof ParametersWithID) {
            baseParam = ((ParametersWithID) param).getParameters();
            userID = ((ParametersWithID) param).getID();
        } else {
            baseParam = param;
            // the default value
            userID = Hex.decode("31323334353637383132333435363738");
        }

        if (forSigning) {
            if (baseParam instanceof ParametersWithRandom) {
                ParametersWithRandom rParam = (ParametersWithRandom) baseParam;

                ecKey = (ECKeyParameters) rParam.getParameters();
                ecParams = ecKey.getParameters();
            } else {
                ecKey = (ECKeyParameters) baseParam;
                ecParams = ecKey.getParameters();
            }
            pubPoint = new FixedPointCombMultiplier().multiply(ecParams.getG(), ((ECPrivateKeyParameters) ecKey).getD()).normalize();
        } else {
            ecKey = (ECKeyParameters) baseParam;
            ecParams = ecKey.getParameters();
            pubPoint = ((ECPublicKeyParameters) ecKey).getQ();
        }

        final SM3Digest digest = new SM3Digest();

        // userId
        int len = userID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userID, 0, userID.length);

        // A | B | G.X | G.Y | Q.X | Q.Y
        byte[] A = ecParams.getCurve().getA().getEncoded();
        digest.update(A, 0, A.length);
        byte[] B = ecParams.getCurve().getB().getEncoded();
        digest.update(B, 0, B.length);
        byte[] GX = ecParams.getG().getAffineXCoord().getEncoded();
        digest.update(GX, 0, GX.length);
        byte[] GY = ecParams.getG().getAffineYCoord().getEncoded();
        digest.update(GY, 0, GY.length);
        byte[] QX = pubPoint.getAffineXCoord().getEncoded();
        digest.update(QX, 0, QX.length);
        byte[] QY = pubPoint.getAffineYCoord().getEncoded();
        digest.update(QY, 0, QY.length);

        // z
        byte[] z = new byte[digest.getDigestSize()];
        digest.doFinal(z, 0);

        digest.reset();
        // Z | InData
        digest.update(z, 0, z.length);
        digest.update(inData, 0, inData.length);

        // eHash
        byte[] eHash = new byte[digest.getDigestSize()];
        digest.doFinal(eHash, 0);

        return eHash;
    }

    /**
     * 对预处理的 hash 值进行签名
     *
     * @param eHash      预处理得到的 hash 值
     * @param privateKey 私钥
     * @param encoding   签名编码器
     * @return 签名
     */
    public static byte[] generateSignature(byte[] eHash, PrivateKey privateKey, DSAEncoding encoding) {

        AsymmetricKeyParameter ecParam;
        try {
            ecParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("PrivateKeyFactory create private key failed", e);
        }

        BigInteger n = EC_PARAMETER_SPEC.getN();
        BigInteger e = calculateE(n, eHash);
        BigInteger d = ((ECPrivateKeyParameters) ecParam).getD();

        BigInteger r, s;

        ECMultiplier basePointMultiplier = new FixedPointCombMultiplier();

        RandomDSAKCalculator kCalculator = new RandomDSAKCalculator();
        kCalculator.init(EC_PARAMETER_SPEC.getN(), CryptoServicesRegistrar.getSecureRandom());

        // 5.2.1 Draft RFC:  SM2 Public Key Algorithms
        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                // A3
                k = kCalculator.nextK();

                // A4
                ECPoint p = basePointMultiplier.multiply(EC_PARAMETER_SPEC.getG(), k).normalize();

                // A5
                r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
            }
            while (r.equals(ECConstants.ZERO) || r.add(k).equals(n));

            // A6
            BigInteger dPlus1ModN = d.add(ECConstants.ONE).modInverse(n);

            s = k.subtract(r.multiply(d)).mod(n);
            s = dPlus1ModN.multiply(s).mod(n);
        }
        while (s.equals(ECConstants.ZERO));

        // A7
        try {
            return encoding.encode(EC_PARAMETER_SPEC.getN(), r, s);
        } catch (Exception ex) {
            throw new RuntimeException("unable to encode signature: " + ex.getMessage(), ex);
        }
    }

    /**
     * 对预处理的 hash 值进行验签
     *
     * @param eHash     预处理得到的 hash 值
     * @param signature 签名
     * @param publicKey SM2 公钥
     * @param encoding  签名编码器
     * @return 验签结果
     */
    public static boolean verifySignature(byte[] eHash, byte[] signature, PublicKey publicKey, DSAEncoding encoding) {
        try {
            AsymmetricKeyParameter ecParam;
            try {
                ecParam = ECUtil.generatePublicKeyParameter(publicKey);
            } catch (InvalidKeyException e) {
                throw new RuntimeException("ECUtil generate public key failed");
            }

            BigInteger[] rs = encoding.decode(EC_PARAMETER_SPEC.getN(), signature);
            BigInteger r = rs[0];
            BigInteger s = rs[1];

            BigInteger n = EC_PARAMETER_SPEC.getN();

            // 5.3.1 Draft RFC:  SM2 Public Key Algorithms
            // B1
            if (r.compareTo(ECConstants.ONE) < 0 || r.compareTo(n) >= 0) {
                return false;
            }

            // B2
            if (s.compareTo(ECConstants.ONE) < 0 || s.compareTo(n) >= 0) {
                return false;
            }

            // B3 is eHash

            // B4
            BigInteger e = calculateE(n, eHash);

            // B5
            BigInteger t = r.add(s).mod(n);
            if (t.equals(ECConstants.ZERO)) {
                return false;
            }

            // B6
            ECPoint q = ((ECPublicKeyParameters) ecParam).getQ();
            ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(EC_PARAMETER_SPEC.getG(), s, q, t).normalize();
            if (x1y1.isInfinity()) {
                return false;
            }

            // B7
            BigInteger expectedR = e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n);

            return expectedR.equals(r);
        } catch (Exception e) {
        }
        return false;
    }

    protected static BigInteger calculateE(BigInteger n, byte[] message) {
        // TODO Should hashes larger than the order be truncated as with ECDSA?
        return new BigInteger(1, message);
    }

}