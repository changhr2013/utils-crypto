package com.changhr.utils.crypto.utils;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

/**
 * 签名工具类
 *
 * @author changhr2013
 */
public class Signers {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * SM2 算法推荐的默认 ID
     */
    private static final byte[] SM2_ID = {
            (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38,
            (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38
    };

    /**
     * Sha256WithRSA 签名
     *
     * @param inData     原始数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static byte[] RSASign(byte[] inData, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256WITHRSA", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(inData);
        return signer.sign();
    }

    /**
     * Sha256WithRSA 验签
     *
     * @param inData    原始数据
     * @param signature 签名
     * @param publicKey 公钥
     * @return boolean 验签结果
     */
    public static boolean RSAVerify(byte[] inData, byte[] signature, PublicKey publicKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256WITHRSA", BouncyCastleProvider.PROVIDER_NAME);
        signer.initVerify(publicKey);
        signer.update(inData);
        return signer.verify(signature);
    }

    /**
     * SM3WithSM2 签名
     *
     * @param inData     原始数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static byte[] SM2Sign(byte[] inData, PrivateKey privateKey) throws Exception {
        AsymmetricKeyParameter ecParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(true, new ParametersWithID(ecParam, SM2_ID));
        sm2Signer.update(inData, 0, inData.length);
        return sm2Signer.generateSignature();
    }

    /**
     * SM3WithSM2 验签
     *
     * @param inData    原始数据
     * @param signature 签名
     * @param publicKey 公钥
     * @return boolean，验签结果
     */
    public static boolean SM2Verify(byte[] inData, byte[] signature, PublicKey publicKey) throws Exception {
        AsymmetricKeyParameter ecParam = ECUtil.generatePublicKeyParameter(publicKey);
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(false, new ParametersWithID(ecParam, SM2_ID));
        sm2Signer.update(inData, 0, inData.length);
        return sm2Signer.verifySignature(signature);
    }

    /**
     * Sha256WithECDSA 签名
     *
     * @param inData     原始数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static byte[] ECDSASign(byte[] inData, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256WITHECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(inData);
        return signer.sign();
    }

    /**
     * Sha256WithECDSA 验签
     *
     * @param inData    原始数据
     * @param signature 签名
     * @param publicKey 公钥
     * @return boolean，验签结果
     */
    public static boolean ECDSAVerify(byte[] inData, byte[] signature, PublicKey publicKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256WITHECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signer.initVerify(publicKey);
        signer.update(inData);
        return signer.verify(signature);
    }

}