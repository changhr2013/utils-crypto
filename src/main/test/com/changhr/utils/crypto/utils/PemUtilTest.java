package com.changhr.utils.crypto.utils;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.StringBufferInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PemUtilTest {

    @Test
    public void testParserPrivateKey() {

        String pemPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEogIBAAKCAQEAoxY+6xzmEw/8Osgu7d/ysyCFKvOJoDChuPl5L1iK0Iy4wDDA\n" +
                "6kHBYMgcttZk1TFcro5P2yDnShwMPP6MvteNpfzTjW/K7xid1V9C2BVjj2amFam1\n" +
                "EDJ7Oj9gHb2DcdvHr8WgcXDyvq578TZE+I7fWqlftuJKiSPQ01NYRnK6vvE6dHHl\n" +
                "BqZFsTUi+gj776zXuPJmz7G6egQP08isw/Nb83/8EcnGi92pHyzpXcSOeUtBW1HF\n" +
                "rbd7zkZIpyRqBrU5KXxozCvZtQbF5/YgmiLKjWfYPoxGqg2xvLsJ6ZHhfnu5qOJv\n" +
                "5eyymdfyE+pxvEnF7H4eyF6AKb+V8Qm4u6cvOwIDAQABAoIBAHGp03gxz/iBL54Y\n" +
                "XvzTFGfbxnRFACpxOoWc+eURpM3tBeaNFCcwZQJ69ehITEZ5/Mp7zRRAPnLcUXtB\n" +
                "Pf7UZJjHOPpea+VwFrDbj87iOV18gUyf1t3PEStreCXCK5ZzQx0yc7wcqFJVcXSQ\n" +
                "Cknh6bFaUqc32BL0r1pZwDB5TcY9ZNsMiro83eJdSUlnFfZe0hAnC/wYg3+0VlGX\n" +
                "+QwSK6SJXlE53hyGYtgrntpBGzDkBIRJ2Qy8Jrmf7ij5DId1hojkVtN5sEnpUY8/\n" +
                "zOdcQ3ONIijVaSIxXrgN0FTHfzJs3r3MCS4vc7m+CBDiuncG4d416jQnUd/z8z6Q\n" +
                "7tawQWECgYEAwJYmvnW9RUFQoLgQs0Q8eEJwrcHGc6jf8MbJPwLNrwxS2XxhRCed\n" +
                "6vl36uwyvzIFZnnfzicvNpOfu1KvjuZBnyuhR6+wqYlmLnEvtyTcBOWVXI98YqFS\n" +
                "94RndzC2af97/wuZmiElf1rV+jJeSTwRX2+Sgk1uf6LQNsINPNFpAO0CgYEA2Ml1\n" +
                "bCkoiSxqr+jgJHSH7r8/2xGGkuH0wvGRF1RxYp1M/6QAd68274tAECTaTcx9WyMB\n" +
                "wOBhSYYHsZ7vopsuzz6+AklWmh+xBw+7ETM5ZQ3YxfI7K56VuziMM2fFANhcHDX2\n" +
                "lhY+kceHNyFnJgCmYcBhMgY3ga+MMhXU1vtxc8cCgYBFU8gOuAOycpi7wocAgYfj\n" +
                "Ise9RQxThm9XFbhMXo38fcs1T3kUN865T6TDhNOf0Dnxcd4HMEPmua2+mT1pi6oD\n" +
                "yoj8bVqDLVsDTOuIWlR5zsu9zklQmBJt19QHLBn+fmH8pghdW6FL/z8YGhmm82Ct\n" +
                "olRzY7xrZgjeLWzmf9v04QKBgHkH+Ju7WttCxgmR/Vm9CYs8kT0QSs7Egi84SOX6\n" +
                "ihchdTSgbnZjh0sztj+NI6gdy7rPD5KMcyRmRPNgpa9l7jtcbx69rTD9Eou7t5gB\n" +
                "vkBx+52AAJL4xeWxy2yDudQf90T0x8fBgYtIF3CrIHhyEnIuwtT37ZNk2+O2lo6z\n" +
                "8QJPAoGABDnvNIkWc/s32xaeqnhVcYRU++kPL7qrhB/DonrQj3cQrMA9Eb/tQ7/J\n" +
                "uIs/0L1mC1tpclC/FrO0PNQ6my4tBrfGwMtfRjCCMjTAEPQXWSYiguk+om+nUN1J\n" +
                "L9GsgiZ5vGMrmkyWshid0c9B8csM6Pe0NZJHm6z/NkK8MmqBNrQ=\n" +
                "-----END RSA PRIVATE KEY-----";

        PrivateKey privateKey = PemUtil.readPemPrivateKey(new ByteArrayInputStream(pemPrivateKey.getBytes(StandardCharsets.UTF_8)));
        System.out.println(privateKey.getAlgorithm());
        System.out.println(privateKey.getFormat());
        System.out.println(Hex.toHexString(privateKey.getEncoded()));

        String pemCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIEFjCCAv6gAwIBAgIQROPHtOwnSxKbq3xfcWWVIjANBgkqhkiG9w0BAQsFADBe\n" +
                "MQswCQYDVQQGEwJDTjEOMAwGA1UEChMFTXlTU0wxKzApBgNVBAsTIk15U1NMIFRl\n" +
                "c3QgUlNBIC0gRm9yIHRlc3QgdXNlIG9ubHkxEjAQBgNVBAMTCU15U1NMLmNvbTAe\n" +
                "Fw0yMjA1MTIxNjM5NTdaFw0yMjA2MTExNjM5NTdaMGExCzAJBgNVBAYTAkNOMRAw\n" +
                "DgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMQ0wCwYDVQQKEwRURVNU\n" +
                "MQ0wCwYDVQQLEwRURVNUMRAwDgYDVQQDEwdhYmMuY29tMIIBIjANBgkqhkiG9w0B\n" +
                "AQEFAAOCAQ8AMIIBCgKCAQEAoxY+6xzmEw/8Osgu7d/ysyCFKvOJoDChuPl5L1iK\n" +
                "0Iy4wDDA6kHBYMgcttZk1TFcro5P2yDnShwMPP6MvteNpfzTjW/K7xid1V9C2BVj\n" +
                "j2amFam1EDJ7Oj9gHb2DcdvHr8WgcXDyvq578TZE+I7fWqlftuJKiSPQ01NYRnK6\n" +
                "vvE6dHHlBqZFsTUi+gj776zXuPJmz7G6egQP08isw/Nb83/8EcnGi92pHyzpXcSO\n" +
                "eUtBW1HFrbd7zkZIpyRqBrU5KXxozCvZtQbF5/YgmiLKjWfYPoxGqg2xvLsJ6ZHh\n" +
                "fnu5qOJv5eyymdfyE+pxvEnF7H4eyF6AKb+V8Qm4u6cvOwIDAQABo4HMMIHJMA4G\n" +
                "A1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYD\n" +
                "VR0jBBgwFoAUKIEmBdE0Gj/Bcw+7k88VHD8Dv38wYwYIKwYBBQUHAQEEVzBVMCEG\n" +
                "CCsGAQUFBzABhhVodHRwOi8vb2NzcC5teXNzbC5jb20wMAYIKwYBBQUHMAKGJGh0\n" +
                "dHA6Ly9jYS5teXNzbC5jb20vbXlzc2x0ZXN0cnNhLmNydDASBgNVHREECzAJggdh\n" +
                "YmMuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAvy+JCTx81N+Azo6vz60SKINCSo9Wj\n" +
                "EV4TZfxCiWnBD8cWoZXJAkMOlkTXJcPvYbFXYsZ+MWHbQ18ec9PfvfnSQ6ib1JUJ\n" +
                "ObMWBbrilDVWBMe+3v3N8je8NgpLNUiFi4HP/CJTJih0wJ2euyOyLs5r1g5oO6hv\n" +
                "erUExaDtMFRAs2GCRUd/6ne7JSUV82/qWXrJDCfU+nGH2ZJFBGyfz7guLdmWUc36\n" +
                "q39kAECPyNjkH/2eKNgwG9VA96Uveqd1Q0gwN4F9I4j6t/5QM7y04pMvW3kZ+C/v\n" +
                "SwZTTBW1OGoP2EXdSRfNP2HmG4GjFQu5Sq5jp5F1d7lcDgLgUDErhugb\n" +
                "-----END CERTIFICATE-----";

        PublicKey publicKey = PemUtil.readPemPublicKey(new ByteArrayInputStream(pemCert.getBytes(StandardCharsets.UTF_8)));
        System.out.println(publicKey.getAlgorithm());
        System.out.println(publicKey.getFormat());
        System.out.println(Hex.toHexString(publicKey.getEncoded()));

        String sm2PemPrivateKey = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIKB89IhhSy9WrtQS7TWO5Yqyv5a3DnogWYUhb3TbzjnWoAoGCCqBHM9V\n" +
                "AYItoUQDQgAE3LRuqCM697gL3jPhw98eGfTDcJsuJr6H1nE4VkgdtBdX3So2lC6m\n" +
                "UGEnWeRZuh8HnzCRobcu02Bgv7CVR5Iigg==\n" +
                "-----END EC PRIVATE KEY-----";
        PrivateKey sm2PrivateKey = PemUtil.readPemPrivateKey(new ByteArrayInputStream(sm2PemPrivateKey.getBytes(StandardCharsets.UTF_8)));
        System.out.println(sm2PrivateKey.getAlgorithm());
        System.out.println(sm2PrivateKey.getFormat());
        System.out.println(Hex.toHexString(sm2PrivateKey.getEncoded()));


        String eccPemCsr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIIBKDCB0AIBADBNMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQMA4G\n" +
                "A1UEBxMHQmVpamluZzEMMAoGA1UEChMDMTIzMQwwCgYDVQQDEwMxMjMwWTATBgcq\n" +
                "hkjOPQIBBggqhkjOPQMBBwNCAAQbSGdKBOUyQLmA1b4oDTdGnDanJZLcnxBRLGkc\n" +
                "KJETqQmX/v1BxrGFXqIHyJBPxiA4B2uL7eF/3hlqZtunplFIoCEwHwYJKoZIhvcN\n" +
                "AQkOMRIwEDAOBgNVHREEBzAFggMxMjMwCgYIKoZIzj0EAwIDRwAwRAIgNKaMUdss\n" +
                "h+mnbZmx7ZhLInWB1FeLtQZ+VWcfNPK7I7wCIHawHN4PoYc2lIYrpIJZQqJXYsRP\n" +
                "63c5qoeXApObdkTn\n" +
                "-----END CERTIFICATE REQUEST-----";
        PublicKey csrPublicKey = PemUtil.readPemPublicKey(new ByteArrayInputStream(eccPemCsr.getBytes(StandardCharsets.UTF_8)));
        System.out.println(csrPublicKey.getAlgorithm());
        System.out.println(csrPublicKey.getFormat());
        System.out.println(Hex.toHexString(csrPublicKey.getEncoded()));
    }
}
