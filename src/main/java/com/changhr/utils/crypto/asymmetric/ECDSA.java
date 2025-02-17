package com.changhr.utils.crypto.asymmetric;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * ECDSA 签名/验签算法工具类
 *
 * @author changhr2013
 */
public class ECDSA {

    public static final String KEY_ALGORITHM = "ECDSA";

    public static final String CURVE_NAME = "secp256k1";

    private static final int RS_LEN = 32;

    public static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";

    private static final X9ECParameters X9_EC_PARAMETERS = SECNamedCurves.getByName(CURVE_NAME);

    private static final ECDomainParameters EC_DOMAIN_PARAMETERS = new ECNamedDomainParameters(SECNamedCurves.getOID(CURVE_NAME), X9_EC_PARAMETERS.getCurve(), X9_EC_PARAMETERS.getG(), X9_EC_PARAMETERS.getN(), X9_EC_PARAMETERS.getH());

    private static final ECParameterSpec EC_PARAMETER_SPEC = new ECNamedCurveParameterSpec(CURVE_NAME, X9_EC_PARAMETERS.getCurve(), X9_EC_PARAMETERS.getG(), X9_EC_PARAMETERS.getN(), X9_EC_PARAMETERS.getH());

    /**
     * 签名
     *
     * @param msg        原文
     * @param privateKey 私钥，{@link PrivateKey}
     * @param digest     摘要算法，{@link Digest}
     * @param encoding   签名的编码方式，{@link DSAEncoding}
     * @return 签名
     */
    public static byte[] sign(byte[] msg, PrivateKey privateKey, Digest digest, DSAEncoding encoding) {
        try {
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(msg, 0);

            ECDSASigner ecdsaSigner = new ECDSASigner();
            AsymmetricKeyParameter privateKeyParameter = ECUtil.generatePrivateKeyParameter(privateKey);
            ecdsaSigner.init(true, new ParametersWithRandom(privateKeyParameter, CryptoServicesRegistrar.getSecureRandom()));
            BigInteger[] bigIntegerArray = ecdsaSigner.generateSignature(hash);

            return encoding.encode(ecdsaSigner.getOrder(), bigIntegerArray[0], bigIntegerArray[1]);
        } catch (Exception e) {
            throw new RuntimeException("ecdsa signature exception", e);
        }
    }

    /**
     * 验签
     *
     * @param msg       原文
     * @param rs        签名
     * @param publicKey 公钥，{@link PublicKey}
     * @param digest    摘要算法，{@link Digest}
     * @param encoding  签名的编码方式，{@link DSAEncoding}
     * @return boolean，验签结果
     */
    public static boolean verify(byte[] msg, byte[] rs, PublicKey publicKey, Digest digest, DSAEncoding encoding) {
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePublicKeyParameter(publicKey);

            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(msg, 0);

            ECDSASigner ecdsaSigner = new ECDSASigner();
            ecdsaSigner.init(false, ecParam);
            BigInteger[] bigIntegerArray = encoding.decode(ecdsaSigner.getOrder(), rs);
            return ecdsaSigner.verifySignature(hash, bigIntegerArray[0], bigIntegerArray[1]);
        } catch (Exception e) {
            throw new RuntimeException("ecdsa verify signature exception", e);
        }
    }

    /**
     * 生成 ECDSA 密钥对
     *
     * @return KeyMap 密钥对
     */
    public static KeyPair initKeyPair() {
        try {
            // 实例化密钥对生成器
            KeyPairGeneratorSpi.ECDSA ecKeyPairGen = new KeyPairGeneratorSpi.ECDSA();
            ecKeyPairGen.initialize(EC_PARAMETER_SPEC, CryptoServicesRegistrar.getSecureRandom());
            return ecKeyPairGen.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException("invalid algorithm parameter exception", e);
        }
    }

    /**
     * 通过私钥计算公钥值
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
     * 从交换私钥还原完整的 BCECPrivateKey
     *
     * @param swapPrivateKey 交换私钥（D 分量字节数组）
     * @return BCECPrivateKey 完整的私钥
     */
    public static BCECPrivateKey buildPrivateKey(byte[] swapPrivateKey) {
        BigInteger d = new BigInteger(1, swapPrivateKey);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, EC_PARAMETER_SPEC);
        return new BCECPrivateKey(KEY_ALGORITHM, ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
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
}
