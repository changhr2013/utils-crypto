package com.changhr.utils.crypto.cert;

import com.changhr.utils.crypto.asymmetric.ECDSA;
import com.changhr.utils.crypto.asymmetric.RSA;
import com.changhr.utils.crypto.asymmetric.SM2;
import com.changhr.utils.crypto.utils.*;
import com.changhr.utils.crypto.utils.Base64;
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
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/**
 * 证书处理相关的工具类
 *
 * @author changhr2013
 */
public class CertificateUtil {

    private CertificateUtil() {
    }

    /**
     * 从 {@link File} 读取证书转换为 {@link java.security.cert.Certificate} 对象
     *
     * @param file 证书文件
     * @return {@link java.security.cert.Certificate}
     */
    public static java.security.cert.Certificate readCertificate(File file) {
        try (FileInputStream inputStream = new FileInputStream(file)) {
            return new CertificateFactory().engineGenerateCertificate(inputStream);
        } catch (Exception e) {
            throw new RuntimeException("read certificate exception.", e);
        }
    }

    /**
     * 转换字节数组为 {@link java.security.cert.Certificate} 证书对象
     *
     * @param certBytes 证书字节数组
     * @return {@link java.security.cert.Certificate}
     */
    public static java.security.cert.Certificate readCertificate(byte[] certBytes) {
        try (ByteArrayInputStream certInputStream = new ByteArrayInputStream(certBytes)) {
            return new CertificateFactory().engineGenerateCertificate(certInputStream);
        } catch (Exception e) {
            throw new RuntimeException("read certificate exception.", e);
        }
    }

    /**
     * 从证书中获取 {@link SubjectPublicKeyInfo} 的字节数组
     *
     * @param certificate 证书，{@link java.security.cert.Certificate}
     * @return {@link SubjectPublicKeyInfo} 字节数组
     */
    public static byte[] getSubjectPublicKeyInfoEncoded(java.security.cert.Certificate certificate) {
        try {
            TBSCertificate tbsCertificate = TBSCertificate.getInstance(((X509Certificate) certificate).getTBSCertificate());
            SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCertificate.getSubjectPublicKeyInfo();
            return subjectPublicKeyInfo.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("pick SubjectPublicKeyInfo exception", e);
        }
    }

    /**
     * 从私钥文件中读取私钥
     *
     * @param file      私钥文件
     * @param algorithm 算法
     * @param password  私钥加密使用的密码
     * @return {@link PrivateKey}
     */
    public static PrivateKey readPrivateKey(File file, String algorithm, String password) {
        try (FileInputStream inputStream = IoUtil.toStream(file)) {
            return readPrivateKey(inputStream, algorithm, password);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 从私钥文件中读取私钥
     *
     * @param inputStream 私钥 IO 流
     * @param algorithm   算法
     * @param password    私钥加密使用的密码
     * @return {@link PrivateKey}
     */
    public static PrivateKey readPrivateKey(InputStream inputStream, String algorithm, String password) {

        try (BufferedInputStream bufferInputStream = new BufferedInputStream(inputStream)) {
            final PemObject object = PemUtil.readPemObject(bufferInputStream);
            final String type = object.getType();
            final byte[] content = object.getContent();

            if ("ENCRYPTED PRIVATE KEY".equalsIgnoreCase(type)) {
                EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(content);
                char[] passwordCharArray = StrUtil.isEmpty(password) ? null : password.toCharArray();
                PBEKeySpec keySpec = new PBEKeySpec(passwordCharArray);
                SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = encryptedPrivateKeyInfo.getKeySpec(pbeKeyFactory.generateSecret(keySpec));

                return KeyUtil.generatePrivateKey(algorithm, pkcs8EncodedKeySpec);
            } else if (type.endsWith("PRIVATE KEY")) {
                return KeyUtil.generatePrivateKey(algorithm, content);
            } else {
                throw new RuntimeException("unsupported pem type[" + type + "]");
            }
        } catch (Exception e) {
            throw new RuntimeException("read private key file exception", e);
        }
    }

    /**
     * 保存私钥为 PKCS#8 PEM 文件
     *
     * @param privateKey 私钥，{@link PrivateKey}
     * @param encryptor  加密器，{@link OutputEncryptor} 实现类
     * @param path       保存的文件路径
     * @return PEM 内容
     */
    public static String savePkcs8ToPemFile(PrivateKey privateKey, OutputEncryptor encryptor, String path) {
        try {
            String pkcs8PemString = PemUtil.generatePemString(new JcaPKCS8Generator(privateKey, encryptor));

            File saveFile = FileUtil.exist(path) ? FileUtil.file(path) : FileUtil.touch(path);
            FileUtil.writeUtf8String(pkcs8PemString, saveFile);

            return pkcs8PemString;
        } catch (Exception e) {
            throw new RuntimeException("save pkcs#8 private key to pem exception", e);
        }
    }

    /**
     * 保存证书为 PEM 文件
     *
     * @param certificate BC 证书，{@link Certificate}
     * @param path        路径
     * @return PEM 内容
     */
    public static String saveX509ToPemFile(Certificate certificate, String path) {
        try {
            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate);
            String certHolderString = PemUtil.generatePemString(new JcaMiscPEMGenerator(certificateHolder));

            File saveFile = FileUtil.exist(path) ? FileUtil.file(path) : FileUtil.touch(path);
            FileUtil.writeUtf8String(certHolderString, saveFile);

            return certHolderString;
        } catch (Exception e) {
            throw new RuntimeException("save x.509 certificate to pem exception", e);
        }
    }

    /**
     * 签发证书
     *
     * @param serialNumber  证书编号
     * @param subject       证书主题，{@link X500Name}
     * @param notBefore     证书起始时间
     * @param notAfter      证书截止时间
     * @param publicKey     证书公钥，{@link PublicKey}
     * @param extensionList 证书扩展列表，{@link Extension}
     * @param issuerCert    签发者证书，{@link Certificate}
     * @param contentSigner 签名器，{@link ContentSigner}
     * @return {@link X509CertificateHolder}
     */
    public static X509CertificateHolder certGen(BigInteger serialNumber, X500Name subject,
                                                Date notBefore, Date notAfter,
                                                PublicKey publicKey, List<Extension> extensionList,
                                                Certificate issuerCert,
                                                ContentSigner contentSigner) throws Exception {

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuerCert.getIssuer(), serialNumber, notBefore, notAfter, subject, subjectPublicKeyInfo);

        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();
        builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCert.getSubjectPublicKeyInfo()))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo));

        if (CollectionUtil.isNotEmpty(extensionList)) {
            for (Extension extension : extensionList) {
                builder.addExtension(extension);
            }
        }

        return builder.build(contentSigner);
    }

    /**
     * 组装证书
     *
     * @param tbsCertificate      {@link TBSCertificate}
     * @param algorithmIdentifier {@link AlgorithmIdentifier}
     * @param signature           签名
     * @return BC 证书，{@link Certificate}
     */
    public static Certificate assembleCert(TBSCertificate tbsCertificate, AlgorithmIdentifier algorithmIdentifier, byte[] signature) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCertificate);
        v.add(algorithmIdentifier);
        v.add(new DERBitString(signature));
        return Certificate.getInstance(new DERSequence(v));
    }

    /**
     * 快速生成自签名证书
     * 注意，此方法会根据公钥算法选择默认的签名算法（SM2WithSM3 | ECDSAWithSHA256 | RSAWithSHA256）
     * 如果需要生成其他签名算法的证书，使用 {@link CertificateUtil#certGen}
     *
     * @param subject   {@link X500Name}
     * @param keyPair   密钥对，{@link KeyPair}
     * @param notBefore 起始时间
     * @param notAfter  结束时间
     * @return BC 证书，{@link Certificate}
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
     * 注意，此方法会根据公钥算法选择默认的签名算法（SM2WithSM3 | ECDSAWithSHA256 | RSAWithSHA256）
     * 如果需要生成其他签名算法的证书，使用 {@link CertificateUtil#certGen}
     *
     * @param tbsCertificate             {@link TBSCertificate}
     * @param issuerSubjectPublicKeyInfo 签发公钥信息，{@link SubjectPublicKeyInfo}
     * @param issuerPrivateKey           签发者私钥，{@link PrivateKey}
     * @return BC 证书，{@link Certificate}
     */
    public static Certificate assembleCert(TBSCertificate tbsCertificate, SubjectPublicKeyInfo issuerSubjectPublicKeyInfo, PrivateKey issuerPrivateKey) throws Exception {
        byte[] signature;
        if ("EC".equalsIgnoreCase(issuerPrivateKey.getAlgorithm())) {
            if (issuerSubjectPublicKeyInfo.getAlgorithm().getParameters().equals(GMObjectIdentifiers.sm2p256v1)) {
                signature = SM2.signWithAsn1(tbsCertificate.getEncoded(), SM2.USER_ID, issuerPrivateKey);
            } else {
                throw new IllegalArgumentException("unsupported curve");
            }
        } else if ("ECDSA".equalsIgnoreCase(issuerPrivateKey.getAlgorithm())) {
            if (issuerSubjectPublicKeyInfo.getAlgorithm().getParameters().equals(SECObjectIdentifiers.secp256k1)) {
                signature = ECDSA.sign(tbsCertificate.getEncoded(), issuerPrivateKey, new SHA256Digest(), StandardDSAEncoding.INSTANCE);
            } else {
                throw new IllegalArgumentException("unsupported curve");
            }
        } else if ("RSA".equalsIgnoreCase(issuerPrivateKey.getAlgorithm())) {
            signature = RSA.sign(tbsCertificate.getEncoded(), issuerPrivateKey, RSA.SHA_256_WITH_RSA);
        } else {
            throw new IllegalArgumentException("unsupported key algorithm");
        }

        return assembleCert(tbsCertificate, getSignAlgorithm(issuerSubjectPublicKeyInfo.getAlgorithm()), signature);
    }

    /**
     * 生成 CSR
     * 注意，此方法使用了默认的签名算法（SM2WithSM3 | ECDSAWithSHA256 | RSAWithSHA256）
     * 如果需要生成其他签名算法的 CSR，使用 {@link org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder}
     *
     * @param subject    {@link X500Name}
     * @param publicKey  公钥，{@link PublicKey}
     * @param privateKey 私钥，{@link PrivateKey}
     * @return CSR，{@link PKCS10CertificationRequest}
     */
    public static PKCS10CertificationRequest generateCSR(X500Name subject, PublicKey publicKey, PrivateKey privateKey) {
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            CertificationRequestInfo info = new CertificationRequestInfo(subject, subjectPublicKeyInfo, new DERSet());
            byte[] signature;
            AlgorithmIdentifier signAlgorithm = getSignAlgorithm(subjectPublicKeyInfo.getAlgorithm());
            if (signAlgorithm.getAlgorithm().equals(GMObjectIdentifiers.sm2sign_with_sm3)) {
                signature = SM2.signWithAsn1(info.getEncoded(ASN1Encoding.DER), SM2.USER_ID, privateKey);
            } else if (signAlgorithm.getAlgorithm().equals(X9ObjectIdentifiers.ecdsa_with_SHA256)) {
                signature = ECDSA.sign(info.getEncoded(ASN1Encoding.DER), privateKey, new SHA256Digest(), StandardDSAEncoding.INSTANCE);
            } else if (signAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
                signature = RSA.sign(info.getEncoded(ASN1Encoding.DER), privateKey, RSA.SHA_256_WITH_RSA);
            } else {
                throw new IllegalArgumentException("unsupported key algorithm");
            }
            return new PKCS10CertificationRequest(new CertificationRequest(info, signAlgorithm, new DERBitString(signature)));
        } catch (Exception e) {
            throw new IllegalArgumentException("illegal key struct", e);
        }
    }

    /**
     * 用于根据公钥算法获取常用的默认签名算法
     *
     * @param algorithmIdentifier 公钥算法 OID 标识
     * @return {@link AlgorithmIdentifier}，签名算法 OID 标识
     */
    protected static AlgorithmIdentifier getSignAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
        // 根据公钥算法标识返回对应签名算法标识
        if (algorithmIdentifier.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)
                && algorithmIdentifier.getParameters().equals(GMObjectIdentifiers.sm2p256v1)) {
            return new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3);
        } else if (algorithmIdentifier.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)
                && algorithmIdentifier.getParameters().equals(SECObjectIdentifiers.secp256k1)) {
            return new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        } else if (algorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption)) {
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
        } else {
            throw new IllegalArgumentException("unsupported key algorithm");
        }
    }

    /**
     * 解析 p7b 内容为证书集合
     *
     * @param p7bInfo p7b，base64 格式
     * @return {@link java.security.cert.Certificate} 证书集合
     */
    public static List<java.security.cert.Certificate> analysisP7bContent(String p7bInfo) {

        try {
            CMSSignedData sd = new CMSSignedData(Base64.decode(p7bInfo));

            Store<X509CertificateHolder> holderStore = sd.getCertificates();

            Collection<X509CertificateHolder> certificateList = holderStore.getMatches(null);

            List<java.security.cert.Certificate> x509List = new ArrayList<>();
            for (X509CertificateHolder x509holder : certificateList) {
                java.security.cert.Certificate x509Certificate = convertCertificate(x509holder);
                x509List.add(x509Certificate);
            }
            return x509List;
        } catch (Exception e) {
            throw new RuntimeException("analysis p7b exception", e);
        }
    }

    /**
     * 将证书链封装为 PKCS#7 规范中的 p7b 格式
     *
     * @param certificateList {@link java.security.cert.Certificate} 证书链列表
     * @return p7b 格式的 {@link PemObject}
     */
    public static PemObject assembleP7bContent(List<java.security.cert.Certificate> certificateList) {
        try {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new JcaCertStore(certificateList));
            CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(null));
            byte[] encoded = signedData.getEncoded();

            return new PemObject("PKCS7", encoded);
        } catch (Exception e) {
            throw new RuntimeException("generate .p7b PEM encode exception", e);
        }
    }

    /**
     * 解析 p7b 内容为 P7bCertificateHolder 对象
     *
     * @param p7bInfo  p7b，base64 格式
     * @param root2end 证书链顺序，true 时表示『根证书在前，终端证书在后』，false 时表示『终端证书在前，根证书在后』
     * @return {@link P7bCertificateHolder}
     */
    public static P7bCertificateHolder splitP7bInfo(String p7bInfo, boolean root2end) {
        List<java.security.cert.Certificate> x509CertificateList = analysisP7bContent(p7bInfo);
        boolean validateResult = CertificateUtil.validateChain(x509CertificateList.toArray(new java.security.cert.Certificate[1]), root2end);
        if (!validateResult) {
            throw new RuntimeException("p7b certificate chain validate failed");
        }

        if (root2end) {
            java.security.cert.Certificate userCertificate = x509CertificateList.get(x509CertificateList.size() - 1);
            x509CertificateList.remove(x509CertificateList.size() - 1);
            return new P7bCertificateHolder(x509CertificateList, userCertificate);
        } else {
            java.security.cert.Certificate userCertificate = x509CertificateList.get(0);
            x509CertificateList.remove(0);
            return new P7bCertificateHolder(x509CertificateList, userCertificate);
        }
    }

    /**
     * 转换 BC X509CertificateHolder 为 JDK Certificate
     *
     * @param x509holder BC {@link X509CertificateHolder}
     * @return JDK {@link java.security.cert.Certificate}
     */
    public static java.security.cert.Certificate convertCertificate(X509CertificateHolder x509holder) {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(x509holder.getEncoded())) {
            return new CertificateFactory().engineGenerateCertificate(byteArrayInputStream);
        } catch (Exception e) {
            throw new RuntimeException("convert bc X509CertificateHolder to Certificate exception", e);
        }
    }

    /**
     * 转换 BC Certificate 为 JDK Certificate
     *
     * @param bcCertificate BC {@link Certificate}
     * @return JDK {@link java.security.cert.Certificate}
     */
    public static java.security.cert.Certificate convertJdkCertificate(Certificate bcCertificate) {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bcCertificate.getEncoded())) {
            return new CertificateFactory().engineGenerateCertificate(byteArrayInputStream);
        } catch (Exception e) {
            throw new RuntimeException("convert bc certificate to jdk certificate exception", e);
        }
    }

    /**
     * 转换 JDK Certificate 为 BC Certificate
     *
     * @param jdkCertificate JDK {@link java.security.cert.Certificate}
     * @return BC {@link Certificate}
     */
    public static Certificate convertBcCertificate(java.security.cert.Certificate jdkCertificate) {
        try {
            return Certificate.getInstance(jdkCertificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("convert jdk certificate to bc certificate exception", e);
        }
    }

    /**
     * 检查证书链，只校验签发者和被签发者的关系
     *
     * @param certChain 证书链，{@link java.security.cert.Certificate} 数组
     * @param root2end  证书链顺序，true 时表示『根证书在前，终端证书在后』，false 时表示『终端证书在前，根证书在后』
     * @return 校验结果，bool
     */
    public static boolean validateChain(java.security.cert.Certificate[] certChain, boolean root2end) {
        if (root2end) {
            for (int i = 0; i < certChain.length - 1; i++) {
                X500Principal subjectDN =
                        ((X509Certificate) certChain[i]).getSubjectX500Principal();
                X500Principal issuerDN =
                        ((X509Certificate) certChain[i + 1]).getIssuerX500Principal();
                if (!(subjectDN.equals(issuerDN))) {
                    return false;
                }
            }
        } else {
            for (int i = 0; i < certChain.length - 1; i++) {
                X500Principal issuerDN =
                        ((X509Certificate) certChain[i]).getIssuerX500Principal();
                X500Principal subjectDN =
                        ((X509Certificate) certChain[i + 1]).getSubjectX500Principal();
                if (!(issuerDN.equals(subjectDN))) {
                    return false;
                }
            }
        }

        // Check for loops in the chain. If there are repeated certs,
        // the Set of certs in the chain will contain fewer certs than
        // the chain
        Set<java.security.cert.Certificate> set = new HashSet<>(Arrays.asList(certChain));
        return set.size() == certChain.length;
    }

    /**
     * 生成 CFCA 能识别的双证 PKCS#10
     *
     * @param x500Name          证书主题，{@link X500Name}
     * @param privateKey        私钥，{@link PrivateKey}
     * @param publicKey         公钥，{@link PublicKey}
     * @param tempPublicKey     临时公钥，{@link PublicKey}
     * @param challengePassword 密码
     * @return {@link PemObject}
     */
    public static PemObject generateCFCASm2CSR(X500Name x500Name, PrivateKey privateKey, PublicKey publicKey, PublicKey tempPublicKey, String challengePassword) {
        try {
            // 第一部分扩展，挑战码
            ASN1ObjectIdentifier challengePasswordOid = new ASN1ObjectIdentifier("1.2.840.113549.1.9.7");
            DERPrintableString asn1Password = new DERPrintableString(challengePassword);

            ASN1EncodableVector passwordVector = new ASN1EncodableVector();
            passwordVector.add(challengePasswordOid);
            passwordVector.add(asn1Password);
            DERSequence sequence1 = new DERSequence(passwordVector);

            // 第二部分，生成随机公钥
            ASN1ObjectIdentifier oid2 = new ASN1ObjectIdentifier("1.2.840.113549.1.9.63");
            ASN1Integer version = new ASN1Integer(1);

            byte[] preBytes = Hex.decode("00B4000000010000");
            byte[] tempPubKeyXBytes = BigIntegers.asUnsignedByteArray(32, ((BCECPublicKey) tempPublicKey).getQ().getXCoord().toBigInteger());
            byte[] zeroBytes1 = new byte[32];
            byte[] tempPubKeyYBytes = BigIntegers.asUnsignedByteArray(32, ((BCECPublicKey) tempPublicKey).getQ().getYCoord().toBigInteger());
            byte[] zeroBytes2 = new byte[32];
            byte[] bodyBytes = org.bouncycastle.util.Arrays.concatenate(tempPubKeyXBytes, zeroBytes1, tempPubKeyYBytes, zeroBytes2);
            byte[] tempPubKeyAsn1Bytes = org.bouncycastle.util.Arrays.concatenate(preBytes, bodyBytes);
            DEROctetString tempPubKey = new DEROctetString(tempPubKeyAsn1Bytes);

            ASN1EncodableVector tempPubKeyChildVector = new ASN1EncodableVector();
            tempPubKeyChildVector.add(version);
            tempPubKeyChildVector.add(tempPubKey);
            DERSequence sequence3 = new DERSequence(tempPubKeyChildVector);

            ASN1EncodableVector tempPubKeyVector = new ASN1EncodableVector();
            tempPubKeyVector.add(oid2);
            tempPubKeyVector.add(new DEROctetString(sequence3));
            DERSequence sequence2 = new DERSequence(tempPubKeyVector);

            // 排列为数组，组装为 TaggedObject
            ASN1Encodable[] encodeArray = new ASN1Encodable[2];
            encodeArray[0] = sequence1;
            encodeArray[1] = sequence2;
            DERTaggedObject attributes = new DERTaggedObject(false, 0, new DERSequence(encodeArray));

            // 组装 CSR Body
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            AlgorithmIdentifier signAlgorithm = CertificateUtil.getSignAlgorithm(subjectPublicKeyInfo.getAlgorithm());

            ASN1EncodableVector cfcaCsrBodyVector = new ASN1EncodableVector(4);
            cfcaCsrBodyVector.add(version);
            cfcaCsrBodyVector.add(x500Name);
            cfcaCsrBodyVector.add(subjectPublicKeyInfo);
            cfcaCsrBodyVector.add(attributes);
            DERSequence cfcaCsrBody = new DERSequence(cfcaCsrBodyVector);

            // SM2 对 Body 签名
            byte[] signature = SM2.signWithAsn1(cfcaCsrBody.getEncoded(ASN1Encoding.DER), SM2.USER_ID, privateKey);

            // 组装 body、algorithm 和 signature
            ASN1EncodableVector csr = new ASN1EncodableVector(3);
            csr.add(cfcaCsrBody);
            csr.add(signAlgorithm);
            csr.add(new DERBitString(signature));
            DERSequence pkcs10CertificationRequest = new DERSequence(csr);

            return new PemObject("CERTIFICATE REQUEST", pkcs10CertificationRequest.getEncoded(ASN1Encoding.DER));
        } catch (Exception e) {
            throw new RuntimeException("generate CFCA CSR exception", e);
        }
    }

    /**
     * 解密 CFCA 生成的双证的加密证书私钥密文
     *
     * @param tempPriKey         申请双证 CSR 时使用的临时私钥
     * @param encryptedPriKeyTxt CFCA 签发双证时生成的加密证书私钥密文
     * @return 加密证书对应的 SM2 密钥对，{@link KeyPair}
     */
    public static KeyPair decodeCFCASm2EncPrivateKey(PrivateKey tempPriKey, String encryptedPriKeyTxt) {
        // 前 80 个字符可能是版本号和字符串长度，此处不使用
        // String preText = encryptedPrivateKeyTxt.substring(0, 80);
        // 从 80 个字符处截断取后半段，将 "," 移除，得到一个 Base64 字符串
        String cipherText = encryptedPriKeyTxt.substring(80);
        String keyPairCipher = cipherText.replaceAll(",", "");

        // 使用 ASN1 解码后，得到一个 EncryptedData 结构
        ASN1Sequence sequence = ASN1Sequence.getInstance(Base64.decode(keyPairCipher));
        String signPrivateKeyCipher = Hex.toHexString(((ASN1OctetString) sequence.getObjectAt(1)).getOctets());
        // EncryptedData 解 ASN1 取 EncryptedContentInfo 部分，得到 ContentHex，在首部添加 04 标识位，构建出标准密文
        String contentHex = "04" + signPrivateKeyCipher;

        // 使用申请 CSR 时使用的临时私钥解密 ContentHex，得到的原文结构为加密证书的裸公私钥，公钥前不带 04 标识（PublicKey + PrivateKey）
        // 因此取前 64 个字节即为加密证书公钥，取剩余的 32 个字节即为加密证书私钥
        byte[] decrypt = SM2.decrypt(Hex.decode(contentHex), tempPriKey);
        byte[] encPubKeyBytes = new byte[65];
        encPubKeyBytes[0] = 0x04;
        System.arraycopy(decrypt, 0, encPubKeyBytes, 1, encPubKeyBytes.length - 1);
        byte[] encPriKeyBytes = new byte[32];
        System.arraycopy(decrypt, 64, encPriKeyBytes, 0, encPriKeyBytes.length);

        // 构建 SM2 密钥对
        return new KeyPair(SM2.buildPublicKey(encPubKeyBytes), SM2.buildPrivateKey(encPriKeyBytes));
    }

}
