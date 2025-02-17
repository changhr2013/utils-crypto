package com.changhr.utils.crypto.cert;

import java.security.cert.Certificate;
import java.util.List;

/**
 * P7b 解析后的证书链和用户证书
 *
 * @author changhr2013
 */
public class P7bCertificateHolder {

    public P7bCertificateHolder() {
    }

    public P7bCertificateHolder(List<Certificate> certificateParentChain, Certificate userCertificate) {
        this.certificateParentChain = certificateParentChain;
        this.userCertificate = userCertificate;
    }

    private List<Certificate> certificateParentChain;

    private Certificate userCertificate;

    public List<Certificate> getCertificateParentChain() {
        return certificateParentChain;
    }

    public void setCertificateParentChain(List<Certificate> certificateParentChain) {
        this.certificateParentChain = certificateParentChain;
    }

    public Certificate getUserCertificate() {
        return userCertificate;
    }

    public void setUserCertificate(Certificate userCertificate) {
        this.userCertificate = userCertificate;
    }
}
