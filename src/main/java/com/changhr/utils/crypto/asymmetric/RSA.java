package com.changhr.utils.crypto.asymmetric;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;

/**
 * 基于 JCE 封装的 RSA 非对称加/解密、签名/验签算法工具类
 *
 * @author changhr2013
 * @create 2019-05-08 14:52
 */
public abstract class RSA {

    /**
     * 密钥算法类型
     */
    public static final String KEY_ALGORITHM = "RSA";

    /**
     * 加解算法/密码本模式/Padding 模式
     */
    public static final String NONE_PKCS_1_PADDING = "RSA/ECB/PKCS1Padding";
    // oaeppadding + MessageDigest.getInstance() 可以识别的 hash 算法名称 + andmgf1padding
    public static final String OAEP_WITH_SHA1_AND_MGF1_PADDING = "RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING";
    public static final String OAEP_WITH_SHA224_AND_MGF1_PADDING = "RSA/ECB/OAEPWITHSHA-224ANDMGF1PADDING";
    public static final String OAEP_WITH_SHA256_AND_MGF1_PADDING = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    public static final String OAEP_WITH_SHA384_AND_MGF1_PADDING = "RSA/ECB/OAEPWITHSHA-384ANDMGF1PADDING";
    public static final String OAEP_WITH_SHA512_AND_MGF1_PADDING = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";

    /**
     * 签名算法
     */
    public static final String SHA_1_WITH_RSA = "SHA1withRSA";
    public static final String SHA_256_WITH_RSA = "SHA256withRSA";
    public static final String SHA_224_WITH_RSA = "SHA224withRSA";
    public static final String SHA_384_WITH_RSA = "SHA384withRSA";
    public static final String SHA_512_WITH_RSA = "SHA512withRSA";
    public static final String SHA_1_WITH_RSA_PSS = "SHA1withRSA/PSS";
    public static final String SHA_224_WITH_RSA_PSS = "SHA224withRSA/PSS";
    public static final String SHA_256_WITH_RSA_PSS = "SHA256withRSA/PSS";
    public static final String SHA_384_WITH_RSA_PSS = "SHA384withRSA/PSS";
    public static final String SHA_512_WITH_RSA_PSS = "SHA512withRSA/PSS";

    /**
     * 公钥
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";

    /**
     * 私钥
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * RSA 密钥长度，默认 2048 位
     * 密钥长度必须是 64 的倍数，范围在 512 ~ 65535 位之间
     */
    private static final int DEFAULT_KEY_SIZE = 2048;

    /**
     * 根据算法类型生成 OAEP 密钥材料
     *
     * @param cipherAlgorithm 算法类型
     * @return OAEP 密钥材料
     */
    private static OAEPParameterSpec generateOAEPSpec(String cipherAlgorithm) {

        switch (cipherAlgorithm) {
            case OAEP_WITH_SHA1_AND_MGF1_PADDING:
                return new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
            case OAEP_WITH_SHA224_AND_MGF1_PADDING:
                return new OAEPParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224, PSource.PSpecified.DEFAULT);
            case OAEP_WITH_SHA256_AND_MGF1_PADDING:
                return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            case OAEP_WITH_SHA384_AND_MGF1_PADDING:
                return new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT);
            case OAEP_WITH_SHA512_AND_MGF1_PADDING:
                return new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
            default:
                return null;
        }
    }

    /**
     * 根据算法类型生成 PSS 签名材料
     *
     * @param signAlgorithm 算法类型
     * @return PSS 签名材料
     */
    private static PSSParameterSpec generatePSSSpec(String signAlgorithm) {
        switch (signAlgorithm) {
            case SHA_1_WITH_RSA_PSS:
                return new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, PSSParameterSpec.DEFAULT.getTrailerField());
            case SHA_224_WITH_RSA_PSS:
                return new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224, 28, PSSParameterSpec.DEFAULT.getTrailerField());
            case SHA_256_WITH_RSA_PSS:
                return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.DEFAULT.getTrailerField());
            case SHA_384_WITH_RSA_PSS:
                return new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, PSSParameterSpec.DEFAULT.getTrailerField());
            case SHA_512_WITH_RSA_PSS:
                return new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, PSSParameterSpec.DEFAULT.getTrailerField());
            default:
                return null;
        }
    }

    /**
     * 获取签名器示例
     *
     * @param signAlgorithm 签名算法
     * @return 实例化好的签名器 {@link Signature}
     */
    private static Signature getSignerInstance(final String signAlgorithm) {
        try {
            Signature signature;
            if (signAlgorithm.endsWith("PSS")) {
                signature = Signature.getInstance("RSASSA-PSS");
                PSSParameterSpec pssParameterSpec = generatePSSSpec(signAlgorithm);
                if (null == pssParameterSpec) {
                    throw new RuntimeException("unsupported sign algorithm " + signAlgorithm);
                }
                signature.setParameter(pssParameterSpec);
            } else {
                signature = Signature.getInstance(signAlgorithm);
            }
            return signature;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 签名
     *
     * @param data   待签名数据
     * @param priKey 私钥字节数组
     * @return byte[] 数字签名
     */
    public static byte[] sign(byte[] data, byte[] priKey, final String signatureAlgorithm) {
        // 转换私钥材料
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(priKey);
        try {
            // 实例化密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 获取私钥对象
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

            return sign(data, privateKey, signatureAlgorithm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return byte[] 数字签名
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey, final String signatureAlgorithm) {
        try {
            // 实例化 Signature
            Signature signature = getSignerInstance(signatureAlgorithm);
            // 初始化 Signature
            signature.initSign(privateKey);
            // 更新
            signature.update(data);
            // 签名
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 验签
     *
     * @param data   待验签数据
     * @param pubKey 公钥字节数组
     * @param sign   数字签名
     * @return boolean 验签通过返回 true，失败返回 false
     */
    public static boolean verify(byte[] data, byte[] pubKey, byte[] sign, final String signatureAlgorithm) {
        // 获取公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubKey);
        try {
            // 实例化密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 生成公钥
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            return verify(data, publicKey, sign, signatureAlgorithm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 验签
     *
     * @param data      待验签数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return boolean 验签通过返回 true，失败返回 false
     */
    public static boolean verify(byte[] data, PublicKey publicKey, byte[] sign, final String signatureAlgorithm) {
        try {
            // 实例化 Signature
            Signature signature = getSignerInstance(signatureAlgorithm);
            // 初始化 Signature
            signature.initVerify(publicKey);
            // 更新
            signature.update(data);
            // 验证
            return signature.verify(sign);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * 公钥加密
     *
     * @param data      待加密数据
     * @param publicKey 公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey, final String cipherAlgorithm) {
        try {
            // 对数据加密
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);

            if (NONE_PKCS_1_PADDING.equals(cipherAlgorithm)) {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            } else {
                OAEPParameterSpec oaepParameterSpec = generateOAEPSpec(cipherAlgorithm);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
            }
            return cipher.doFinal(data);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 公钥加密
     *
     * @param data   待加密数据
     * @param pubKey 公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] data, byte[] pubKey, final String cipherAlgorithm) {
        // 获取公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 生成公钥
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            // 对数据加密
            return encrypt(data, publicKey, cipherAlgorithm);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 公钥加密
     * 默认使用 RSA/ECB/PKCS1Padding 方式
     *
     * @param data   待加密数据
     * @param pubKey 公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] data, byte[] pubKey) {
        return encrypt(data, pubKey, NONE_PKCS_1_PADDING);
    }

    /**
     * 私钥解密
     *
     * @param data            待解密数据
     * @param privateKey      私钥
     * @param cipherAlgorithm 算法/工作模式/填充方式
     * @return byte[] 解密数据
     */
    public static byte[] decrypt(byte[] data, PrivateKey privateKey, final String cipherAlgorithm) {
        try {
            // 对数据解密
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);

            if (NONE_PKCS_1_PADDING.equals(cipherAlgorithm)) {
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            } else {
                OAEPParameterSpec oaepParameterSpec = generateOAEPSpec(cipherAlgorithm);
                cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
            }
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 私钥解密
     *
     * @param data            待解密数据
     * @param priKey          私钥，PKCS#8 格式
     * @param cipherAlgorithm 算法/工作模式/填充方式
     * @return byte[] 解密数据
     */
    public static byte[] decrypt(byte[] data, byte[] priKey, final String cipherAlgorithm) {
        // 获取私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(priKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            // 生成私钥
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            // 对数据解密
            return decrypt(data, privateKey, cipherAlgorithm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 私钥解密
     * 默认使用 RSA/ECB/PKCS1Padding 方式
     *
     * @param data   待解密数据
     * @param priKey 私钥
     * @return byte[] 解密数据
     */
    public static byte[] decrypt(byte[] data, byte[] priKey) {
        return decrypt(data, priKey, NONE_PKCS_1_PADDING);
    }

    /**
     * 获取私钥
     *
     * @param keyMap 密钥 Map
     * @return byte[] 私钥
     */
    public static byte[] getPrivateKey(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    /**
     * 获取公钥
     *
     * @param keyMap 密钥 Map
     * @return byte[] 公钥
     */
    public static byte[] getPublicKey(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }

    /**
     * 通过 RSA 私钥计算公钥
     *
     * @param privateKey RSA 私钥
     * @return RSA 公钥
     */
    public static PublicKey computePublicKey(PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateCrtKey) {
            try {
                RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
                return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(rsaPublicKeySpec);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new RuntimeException("unsupported rsa private key type");
        }
    }

    /**
     * 初始化密钥
     * 默认密钥长度为 2048 位
     *
     * @return 密钥 Map
     */
    public static Map<String, Object> initKey() {
        return initKey(DEFAULT_KEY_SIZE);
    }

    /**
     * 初始化密钥
     *
     * @param keySize 密钥长度
     * @return 密钥 Map
     */
    public static Map<String, Object> initKey(int keySize) {
        // 生成密钥对
        KeyPair keyPair = initKeyPair(keySize);
        // 封装密钥
        Map<String, Object> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());
        return keyMap;
    }

    /**
     * 初始化密钥对
     *
     * @param keySize 密钥长度
     * @return 密钥对，{@link KeyPair}
     */
    public static KeyPair initKeyPair(int keySize) {
        // 实例化密钥对生成器
        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("no such algorithm: " + KEY_ALGORITHM, e);
        }
        // 初始化密钥对生成器
        keyPairGen.initialize(keySize);
        // 生成密钥对
        return keyPairGen.generateKeyPair();
    }

}