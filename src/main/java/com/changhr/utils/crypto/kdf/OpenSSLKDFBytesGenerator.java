package com.changhr.utils.crypto.kdf;

import org.bouncycastle.crypto.*;

/**
 * OpenSSL KDF Generator
 *
 * @author changhr2013
 */
public class OpenSSLKDFBytesGenerator implements DigestDerivationFunction {

    private Digest digest;

    private byte[] password;

    private byte[] salt;

    public OpenSSLKDFBytesGenerator(Digest digest) {
        this.digest = digest;
    }

    @Override
    public void init(DerivationParameters param) {

        if (param instanceof OpenSSLKDFParameters) {

            OpenSSLKDFParameters params = (OpenSSLKDFParameters) param;
            this.password = params.getPassword();
            this.salt = params.getSalt();

        } else {
            throw new IllegalArgumentException("need OpenSSLKDFParameters");
        }
    }

    @Override
    public int generateBytes(byte[] out, int outOff, int len)
            throws DataLengthException, IllegalArgumentException {

        if ((out.length - len) < outOff) {
            throw new OutputLengthException("output buffer too small");
        }

        final int length = digest.getDigestSize();

        final byte[] buffer = new byte[length];

        while (true) {
            /* Add the key and salt */
            digest.update(password, 0, password.length);
            digest.update(salt, 0, Math.min(salt.length, 8));

            /* Calculate the digest and copy it in the result buffer */
            digest.doFinal(buffer, 0);
            final int x = out.length - outOff;
            final int needed = Math.min(x, length);
            System.arraycopy(buffer, 0, out, outOff, needed);

            /* Need more data? */
            if ((outOff += length) >= out.length) {
                break;
            }

            /* Prepare for the next iteration */
            digest.update(buffer, 0, buffer.length);
        }

        digest.reset();

        return len;
    }

    @Override
    public Digest getDigest() {
        return this.digest;
    }

}
