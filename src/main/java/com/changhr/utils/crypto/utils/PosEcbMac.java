package com.changhr.utils.crypto.utils;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

public class PosEcbMac implements Mac {

    private byte[] mac;

    private int macSize;

    private BlockCipher cipher;

    private BlockCipherPadding padding;

    private byte[] buf;

    private int bufOff;

    public PosEcbMac(byte[] iv, BlockCipher cipher, int macSizeInBits) {
        if ((macSizeInBits % 8) != 0) {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }

        this.mac = iv;
        this.macSize = macSizeInBits / 8;
        this.cipher = cipher;
        this.padding = null;

        buf = new byte[cipher.getBlockSize()];
        bufOff = 0;
    }

    @Override
    public void init(CipherParameters params) throws IllegalArgumentException {
        reset();

        cipher.init(true, params);
    }

    @Override
    public String getAlgorithmName() {
        return cipher.getAlgorithmName();
    }

    @Override
    public int getMacSize() {
        return macSize;
    }

    @Override
    public void update(byte in) throws IllegalStateException {
        if (bufOff == buf.length) {
            xor(buf, 0, mac, mac.length);
            bufOff = 0;
        }

        buf[bufOff++] = in;
    }

    @Override
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        int blockSize = cipher.getBlockSize();
        int gapLen = blockSize - bufOff;

        if (len > gapLen) {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            xor(mac, 0, buf, gapLen);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize) {
                xor(in, inOff, mac, mac.length);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;
    }

    @Override
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        int blockSize = cipher.getBlockSize();

        if (padding == null) {
            //
            // pad with zeroes
            //
            while (bufOff < blockSize) {
                buf[bufOff] = 0;
                bufOff++;
            }
        } else {
            if (bufOff == blockSize) {
                xor(buf, 0, mac, mac.length);
                bufOff = 0;
            }

            padding.addPadding(buf, bufOff);
        }

        xor(buf, 0, mac, mac.length);

        byte[] ascii = Hex.toHexString(mac).toUpperCase().getBytes(StandardCharsets.US_ASCII);

        byte[] left = new byte[mac.length];
        System.arraycopy(ascii, 0, left, 0, left.length);

        byte[] right = new byte[mac.length];
        System.arraycopy(ascii, left.length, right, 0, right.length);

        byte[] mid = new byte[mac.length];
        cipher.processBlock(left, 0, mid, 0);

        xor(mid, 0, right, right.length);

        cipher.processBlock(right, 0, mid, 0);

        byte[] ascii2 = Hex.toHexString(mid).toUpperCase().getBytes(StandardCharsets.US_ASCII);

        System.arraycopy(ascii2, 0, out, outOff, macSize);

        reset();

        return macSize;
    }

    @Override
    public void reset() {
        /*
         * clean the buffer.
         */
        for (int i = 0; i < buf.length; i++) {
            buf[i] = 0;
        }

        bufOff = 0;

        /*
         * reset the underlying cipher.
         */
        cipher.reset();
    }

    private static void xor(byte[] left, int leftOff, byte[] right, int rightLen) {
        for (int i = 0; i < rightLen; ++i) {
            right[i] ^= left[leftOff + i];
        }
    }
}
