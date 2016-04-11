/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * @author ahonore
 *
 */
public class CertificateData
{
    private byte[] encodedCertificate;

    public CertificateData()
    {
        this(new byte[]{});
    }

    public CertificateData(byte[] encodedCertificate)
    {
        this.encodedCertificate = encodedCertificate;
    }

    public CertificateData(Certificate certificate) throws CertificateEncodingException
    {
        if (certificate == null)
        {
            this.encodedCertificate = new byte[]{};
        }
        else
        {
            this.encodedCertificate = certificate.getEncoded();
        }
    }

    public byte[] getEncodedCertificate()
    {
        return encodedCertificate;
    }

    public void setEncodedCertificate(byte[] encodedCertificate)
    {
        this.encodedCertificate = encodedCertificate;
    }

    public Certificate getCertificate() throws IOException, CertificateException
    {
        return CryptoTools.decodeCertificate(getEncodedCertificate());
    }
}
