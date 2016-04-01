/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.util.Date;
import java.util.List;

/**
 * @author ahonore
 *
 */
public class CertificatesEntry extends KeyStoreEntry
{
    private List<CertificateData> certificates;

    public CertificatesEntry()
    {
        super();
    }

    public CertificatesEntry(String alias, Date creationDate, List<CertificateData> certificates)
    {
        super(alias, creationDate);
        setCertificates(certificates);
    }

    public List<CertificateData> getCertificates()
    {
        return certificates;
    }

    public void setCertificates(List<CertificateData> certificates)
    {
        this.certificates = certificates;
        addAliasToFirstCertificateNames();
    }
    
    private void addAliasToFirstCertificateNames()
    {
        if (!certificates.isEmpty())
            certificates.get(0).getNames().add(getAlias());
    }
}
