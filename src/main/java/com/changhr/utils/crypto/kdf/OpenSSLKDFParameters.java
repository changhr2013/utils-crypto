package com.changhr.utils.crypto.kdf;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.util.Arrays;

/**
 * Parameter class for the OpenSSLKDFBytesGenerator class.
 *
 * @author changhr2013
 */
public class OpenSSLKDFParameters implements DerivationParameters {

    private final byte[] password;
    private final byte[] salt;

    public OpenSSLKDFParameters(final byte[] password, final byte[] salt) {
        if (password == null) {
            throw new IllegalArgumentException("password should not be null");
        }

        if (salt == null) {
            throw new IllegalArgumentException("salt should not be null");
        }

        this.password = password;

        this.salt = salt;
    }

    /**
     * Returns the password.
     *
     * @return password
     */
    public byte[] getPassword() {
        return Arrays.clone(password);
    }

    /**
     * Returns the salt
     *
     * @return salt
     */
    public byte[] getSalt() {
        return Arrays.clone(salt);
    }

}
