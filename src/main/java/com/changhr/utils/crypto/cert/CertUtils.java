package com.changhr.utils.crypto.cert;

import com.changhr.utils.crypto.utils.KeyUtil;
import com.changhr.utils.crypto.utils.Signers;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

/**
 * 证书相关的工具类
 *
 * @author changhr2013
 */
public class CertUtils {

    /**
     * 生成 CSR
     *
     * @param subject    X509Name
     * @param publicKey  公钥
     * @param privateKey 私钥
     * @return CSR
     */
    public static PKCS10CertificationRequest generateCSR(X500Name subject, PublicKey publicKey, PrivateKey privateKey) {
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            CertificationRequestInfo info = new CertificationRequestInfo(subject, subjectPublicKeyInfo, new DERSet());
            byte[] signature;
            AlgorithmIdentifier signAlgorithm = getSignAlgorithm(subjectPublicKeyInfo.getAlgorithm());
            if (signAlgorithm.getAlgorithm().equals(GMObjectIdentifiers.sm2sign_with_sm3)) {
                signature = Signers.SM2Sign(info.getEncoded(ASN1Encoding.DER), privateKey);
            } else if (signAlgorithm.getAlgorithm().equals(X9ObjectIdentifiers.ecdsa_with_SHA256)) {
                signature = Signers.ECDSASign(info.getEncoded(ASN1Encoding.DER), privateKey);
            } else if (signAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
                signature = Signers.RSASign(info.getEncoded(ASN1Encoding.DER), privateKey);
            } else {
                throw new IllegalArgumentException("密钥算法不支持");
            }
            return new PKCS10CertificationRequest(new CertificationRequest(info, signAlgorithm, new DERBitString(signature)));
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalArgumentException("密钥结构错误");
        }
    }

    /**
     * 生成实体证书
     *
     * @param csr              CSR
     * @param issuerPrivateKey 签发者私钥
     * @param issuerCert       签发者证书
     * @param notBefore        起始时间
     * @param notAfter         结束时间
     * @return 证书
     */
    public static Certificate certGen(PKCS10CertificationRequest csr, PrivateKey issuerPrivateKey,
                                      byte[] issuerCert, Date notBefore, Date notAfter) throws Exception {
        X509CertificateHolder issuer = new X509CertificateHolder(issuerCert);
        if (!verifyCSR(csr)) {
            throw new IllegalArgumentException("证书请求验证失败");
        }
        X500Name subject = csr.getSubject();
        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        // entity cert
        extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        // 授权密钥标识
        extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuer));
        // 使用者密钥标识
        extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE));
        tbsGen.setIssuer(issuer.getSubject());
        tbsGen.setStartDate(new Time(notBefore, Locale.CHINA));
        tbsGen.setEndDate(new Time(notAfter, Locale.CHINA));
        tbsGen.setSubject(subject);
        tbsGen.setSubjectPublicKeyInfo(csr.getSubjectPublicKeyInfo());
        tbsGen.setExtensions(extensionsGenerator.generate());
        // 签名算法标识等于颁发者证书的密钥算法标识
        tbsGen.setSignature(issuer.getSubjectPublicKeyInfo().getAlgorithm());
        TBSCertificate tbs = tbsGen.generateTBSCertificate();
        return assembleCert(tbs, issuer.getSubjectPublicKeyInfo(), issuerPrivateKey);
    }

    /**
     * 生成自签名证书
     *
     * @param subject   X500Name
     * @param keyPair   密钥对
     * @param notBefore 起始时间
     * @param notAfter  结束时间
     * @return 证书
     */
    public static Certificate selfSignedCertGen(X500Name subject, KeyPair keyPair, Date notBefore, Date notAfter) throws Exception {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        // ca cert
        extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo));
        extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo));
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE));
        // 自签证书颁发者等于使用者
        tbsGen.setIssuer(subject);
        tbsGen.setStartDate(new Time(notBefore, Locale.CHINA));
        tbsGen.setEndDate(new Time(notAfter, Locale.CHINA));
        tbsGen.setSubject(subject);
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        tbsGen.setExtensions(extensionsGenerator.generate());
        // 签名算法标识等于密钥算法标识
        tbsGen.setSignature(getSignAlgorithm(subjectPublicKeyInfo.getAlgorithm()));
        TBSCertificate tbs = tbsGen.generateTBSCertificate();
        return assembleCert(tbs, subjectPublicKeyInfo, keyPair.getPrivate());
    }

    /**
     * 组装证书
     *
     * @param tbsCertificate             TBSCertificate
     * @param issuerSubjectPublicKeyInfo 签发公钥信息
     * @param issuerPrivateKey           签发者私钥
     * @return 证书
     */
    public static Certificate assembleCert(TBSCertificate tbsCertificate, SubjectPublicKeyInfo issuerSubjectPublicKeyInfo, PrivateKey issuerPrivateKey) throws Exception {
        byte[] signature;
        if ("ECDSA".equalsIgnoreCase(issuerPrivateKey.getAlgorithm())) {
            if (issuerSubjectPublicKeyInfo.getAlgorithm().getParameters().equals(GMObjectIdentifiers.sm2p256v1)) {
                signature = Signers.SM2Sign(tbsCertificate.getEncoded(), issuerPrivateKey);
            } else if (issuerSubjectPublicKeyInfo.getAlgorithm().getParameters().equals(SECObjectIdentifiers.secp256k1)) {
                signature = Signers.ECDSASign(tbsCertificate.getEncoded(), issuerPrivateKey);
            } else {
                throw new IllegalArgumentException("不支持的曲线");
            }
        } else if ("RSA".equalsIgnoreCase(issuerPrivateKey.getAlgorithm())) {
            signature = Signers.RSASign(tbsCertificate.getEncoded(), issuerPrivateKey);
        } else {
            throw new IllegalArgumentException("不支持的密钥算法");
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCertificate);
        v.add(getSignAlgorithm(issuerSubjectPublicKeyInfo.getAlgorithm()));
        v.add(new DERBitString(signature));
        return Certificate.getInstance(new DERSequence(v));
    }

    /**
     * 验证 CSR
     *
     * @param csr CSR
     * @return boolean
     */
    public static boolean verifyCSR(PKCS10CertificationRequest csr) throws Exception {
        byte[] signature = csr.getSignature();
        if (csr.getSignatureAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm2sign_with_sm3)) {
            return Signers.SM2Verify(csr.toASN1Structure().getCertificationRequestInfo().getEncoded(ASN1Encoding.DER), signature, KeyUtil.getPublicKey(csr.getSubjectPublicKeyInfo()));
        } else if (csr.getSignatureAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.ecdsa_with_SHA256)) {
            return Signers.ECDSAVerify(csr.toASN1Structure().getCertificationRequestInfo().getEncoded(ASN1Encoding.DER), signature, KeyUtil.getPublicKey(csr.getSubjectPublicKeyInfo()));
        } else if (csr.getSignatureAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
            return Signers.RSAVerify(csr.toASN1Structure().getCertificationRequestInfo().getEncoded(ASN1Encoding.DER), signature, KeyUtil.getPublicKey(csr.getSubjectPublicKeyInfo()));
        } else {
            throw new IllegalArgumentException("不支持的签名算法");
        }
    }

    /**
     * 获取签名算法标识
     *
     * @param algorithmIdentifier 算法 Oid 标识
     * @return AlgorithmIdentifier
     */
    static AlgorithmIdentifier getSignAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
        // 根据公钥算法标识返回对应签名算法标识
        if (algorithmIdentifier.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)
                && algorithmIdentifier.getParameters().equals(GMObjectIdentifiers.sm2p256v1)) {
            return new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3, DERNull.INSTANCE);
        } else if (algorithmIdentifier.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey) && algorithmIdentifier.getParameters().equals(SECObjectIdentifiers.secp256k1)) {
            return new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        } else if (algorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption)) {
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
        } else {
            throw new IllegalArgumentException("密钥算法不支持");
        }
    }

}