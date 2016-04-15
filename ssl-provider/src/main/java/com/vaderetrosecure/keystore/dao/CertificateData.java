/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * Represent a Certificate as a byte array, easily readable and writable in a simple data field.
 * 
 * @author ahonore
 *
 */
public class CertificateData
{
    private byte[] encodedCertificate;

    /**
     * Construct a new CertificateData with empty data. 
     */
    public CertificateData()
    {
        this(new byte[]{});
    }

    /**
     * Construct a new CertificateData with a certificate given as a array of bytes.
     * 
     * @param encodedCertificate an array of bytes representing a certificate.
     */
    public CertificateData(byte[] encodedCertificate)
    {
        this.encodedCertificate = encodedCertificate;
    }

    /**
     * Construct a new CertificateData with a certificate object.

     * @param certificate the certificate.
     * @throws CertificateEncodingException if the certificate can not be transformed into an array of byte.
     */
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

    /**
     * Return the encoded certificate, i.e. the array of bytes.
     * 
     * @return the certificate encoded as an array of bytes.
     */
    public byte[] getEncodedCertificate()
    {
        return encodedCertificate;
    }

    /**
     * Set the certificate as an encoded array of bytes.
     * 
     * @param encodedCertificate an array of bytes, representing the certificate.
     */
    public void setEncodedCertificate(byte[] encodedCertificate)
    {
        this.encodedCertificate = encodedCertificate;
    }

    /**
     * Return the Certificate object from the encoded array of bytes of this object.
     * 
     * @return the certificate
     * @throws IOException if the array of bytes can not be read.
     * @throws CertificateException if the Certificate object can not be created from the array of bytes.
     */
    public Certificate getCertificate() throws IOException, CertificateException
    {
        return CryptoTools.decodeCertificate(getEncodedCertificate());
    }
}
