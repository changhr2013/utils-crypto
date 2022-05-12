package com.changhr.utils.crypto.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

public class PemUtil {

    /**
     * 读取 PEM 格式的私钥
     *
     * @param pemStream PEM 流
     * @return {@link PrivateKey}
     */
    public static PrivateKey readPemPrivateKey(InputStream pemStream) {
        return readPemPrivateKey(pemStream, null);
    }

    /**
     * 读取 PEM 格式的私钥
     *
     * @param pemStream PEM 流
     * @param password  密码
     * @return {@link PrivateKey}
     */
    public static PrivateKey readPemPrivateKey(InputStream pemStream, final char[] password) {

        final Provider provider = new BouncyCastleProvider();

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(pemStream))) {

            Object keyObject = pemParser.readObject();

            JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter().setProvider(provider);

            if (keyObject instanceof PrivateKeyInfo) {
                // PrivateKeyInfo
                return pemKeyConverter.getPrivateKey((PrivateKeyInfo) keyObject);
            } else if (keyObject instanceof PEMKeyPair) {
                // PemKeyPair
                return pemKeyConverter.getKeyPair((PEMKeyPair) keyObject).getPrivate();
            } else if (keyObject instanceof PKCS8EncryptedPrivateKeyInfo) {
                // Encrypted PrivateKeyInfo
                InputDecryptorProvider decryptProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(provider).build(password);
                PrivateKeyInfo privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyObject).decryptPrivateKeyInfo(decryptProvider);
                return pemKeyConverter.getPrivateKey(privateKeyInfo);
            } else if (keyObject instanceof PEMEncryptedKeyPair) {
                // Encrypted PemKeyPair
                PEMDecryptorProvider decryptProvider = new JcePEMDecryptorProviderBuilder().setProvider(provider).build(password);
                PrivateKeyInfo privateKeyInfo = ((PEMEncryptedKeyPair) keyObject).decryptKeyPair(decryptProvider).getPrivateKeyInfo();
                return pemKeyConverter.getPrivateKey(privateKeyInfo);
            } else {
                throw new RuntimeException("unsupported private key pem string");
            }

        } catch (IOException | OperatorCreationException | PKCSException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 读取 PEM 格式的公钥
     *
     * @param pemStream PEM 流
     * @return {@link PublicKey}
     */
    public static PublicKey readPemPublicKey(InputStream pemStream) {
        final Provider provider = new BouncyCastleProvider();

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(pemStream))) {

            Object keyObject = pemParser.readObject();

            JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter().setProvider(provider);

            if (keyObject instanceof SubjectPublicKeyInfo) {
                // SubjectPublicKeyInfo
                return pemKeyConverter.getPublicKey((SubjectPublicKeyInfo) keyObject);
            } else if (keyObject instanceof X509CertificateHolder) {
                // X509 Certificate
                return pemKeyConverter.getPublicKey(((X509CertificateHolder) keyObject).getSubjectPublicKeyInfo());
            } else if (keyObject instanceof PEMKeyPair) {
                // PemKeyPair
                return pemKeyConverter.getKeyPair((PEMKeyPair) keyObject).getPublic();
            } else if (keyObject instanceof X509TrustedCertificateBlock) {
                // X509 Trusted Certificate
                return pemKeyConverter.getPublicKey(((X509TrustedCertificateBlock) keyObject).getCertificateHolder().getSubjectPublicKeyInfo());
            } else if (keyObject instanceof PKCS10CertificationRequest) {
                // PKCS#10 CSR
                return pemKeyConverter.getPublicKey(((PKCS10CertificationRequest) keyObject).getSubjectPublicKeyInfo());
            } else {
                throw new RuntimeException("unsupported public key pem string");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 从pem流中读取公钥或私钥
     *
     * @param keyStream pem流
     * @return 密钥bytes
     * @since 5.1.6
     */
    public static byte[] readPem(InputStream keyStream) {
        PemObject pemObject = readPemObject(keyStream);
        if (null != pemObject) {
            return pemObject.getContent();
        }
        return null;
    }

    /**
     * 读取pem文件中的信息，包括类型、头信息和密钥内容
     *
     * @param keyStream pem流
     * @return {@link PemObject}
     * @since 4.5.2
     */
    public static PemObject readPemObject(InputStream keyStream) {
        return readPemObject(new InputStreamReader(keyStream));
    }

    /**
     * 读取pem文件中的信息，包括类型、头信息和密钥内容
     *
     * @param reader pem Reader
     * @return {@link PemObject}
     * @since 5.1.6
     */
    public static PemObject readPemObject(Reader reader) {
        try (PemReader pemReader = new PemReader(reader)) {
            return pemReader.readPemObject();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 将私钥或公钥转换为PEM格式的字符串
     *
     * @param type    密钥类型（私钥、公钥、证书）
     * @param content 密钥内容
     * @return PEM内容
     * @since 5.5.9
     */
    public static String toPem(String type, byte[] content) {
        final StringWriter stringWriter = new StringWriter();
        writePemObject(type, content, stringWriter);
        return stringWriter.toString();
    }

    /**
     * 写出pem密钥（私钥、公钥、证书）
     *
     * @param type      密钥类型（私钥、公钥、证书）
     * @param content   密钥内容，需为PKCS#1格式
     * @param keyStream pem流
     * @since 5.1.6
     */
    public static void writePemObject(String type, byte[] content, OutputStream keyStream) {
        writePemObject(new PemObject(type, content), keyStream);
    }

    /**
     * 写出pem密钥（私钥、公钥、证书）
     *
     * @param type    密钥类型（私钥、公钥、证书）
     * @param content 密钥内容，需为PKCS#1格式
     * @param writer  pemWriter
     * @since 5.5.9
     */
    public static void writePemObject(String type, byte[] content, Writer writer) {
        writePemObject(new PemObject(type, content), writer);
    }

    /**
     * 写出pem密钥（私钥、公钥、证书）
     *
     * @param pemObject pem对象，包括密钥和密钥类型等信息
     * @param keyStream pem流
     * @since 5.1.6
     */
    public static void writePemObject(PemObjectGenerator pemObject, OutputStream keyStream) {
        writePemObject(pemObject, new OutputStreamWriter(keyStream));
    }

    /**
     * 写出pem密钥（私钥、公钥、证书）
     *
     * @param pemObject pem对象，包括密钥和密钥类型等信息
     * @param writer    pemWriter
     * @since 5.5.9
     */
    public static void writePemObject(PemObjectGenerator pemObject, Writer writer) {
        try (PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(pemObject);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
