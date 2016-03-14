/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import javax.security.cert.Certificate;

/**
 * @author ahonore
 *
 */
public class CertificateEntry
{
    private String alias;
    private String chainRank;
    private Certificate certificate;

    public CertificateEntry()
    {
        this("", "", null);
    }
    
    public CertificateEntry(String alias, String chainRank, Certificate certificate)
    {
        super();
        this.alias = alias;
        this.chainRank = chainRank;
        this.certificate = certificate;
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public String getChainRank()
    {
        return chainRank;
    }

    public void setChainRank(String chainRank)
    {
        this.chainRank = chainRank;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public void setCertificate(Certificate certificate)
    {
        this.certificate = certificate;
    }
}
