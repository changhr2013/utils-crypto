package com.changhr.utils.crypto.utils;

import com.changhr.utils.crypto.provider.UnlimitedHolder;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.*;

public class KeyUtils {

    public static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    static {
        UnlimitedHolder.init();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 生成非对称算法密钥对
     *
     * @param algorithm 算法类型
     * @return KeyPair
     */
    public static KeyPair generateKeyPair(String algorithm)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        SecureRandom random = new SecureRandom();

        KeyPairGenerator keyPairGenerator;
        if ("RSA".equalsIgnoreCase(algorithm)) {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA", BC);
            keyPairGenerator.initialize(2048, random);
        } else if ("SM2".equalsIgnoreCase(algorithm)) {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", BC);
            keyPairGenerator.initialize(ecSpec, random);
        } else if ("ECC".equalsIgnoreCase(algorithm)) {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", BC);
            keyPairGenerator.initialize(ecSpec, random);
        } else {
            throw new IllegalArgumentException("不支持的算法：" + algorithm);
        }

        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 从公钥信息中获取公钥
     *
     * @param subjectPublicKeyInfo 公钥信息
     * @return 公钥
     */
    public static PublicKey getPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws Exception {
        BouncyCastleProvider bouncyCastleProvider = ((BouncyCastleProvider) Security.getProvider(BC));
        bouncyCastleProvider.addKeyInfoConverter(PKCSObjectIdentifiers.rsaEncryption, new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi());
        bouncyCastleProvider.addKeyInfoConverter(X9ObjectIdentifiers.id_ecPublicKey, new org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC());
        return BouncyCastleProvider.getPublicKey(subjectPublicKeyInfo);
    }
}