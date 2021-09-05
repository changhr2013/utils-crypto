package com.changhr.utils.crypto.hash;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class HMACUtilTest {

    @Test
    public void MD5ToHex() {
        byte[] key = HMACUtil.initHmacMD5Key();
        System.out.println(Hex.toHexString(key));
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        String s = HMACUtil.MD5ToHex(data, key);
        System.out.println(s);
    }

    @Test
    public void SHA256ToHex() {
        byte[] key = HMACUtil.initHmacSHA256Key();
        System.out.println(Hex.toHexString(key));
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        String s = HMACUtil.SHA256ToHex(data, key);
        System.out.println(s);
    }

    @Test
    public void SM3ToHex() {
        byte[] key = HMACUtil.initHmacSM3Key();
        System.out.println(Hex.toHexString(key));
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        String s = HMACUtil.SM3ToHex(data, key);
        System.out.println(s);
    }
}