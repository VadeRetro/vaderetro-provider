/**
 * 
 */
package com.vaderetrosecure;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author ahonore
 *
 */
public class AccountCertificateInfo
{
    private String hostname;
    private PrivateKey privateKey;
    private List<Certificate> certificateChain;
    
    public AccountCertificateInfo()
    {
        this("", null, new ArrayList<>());
    }

    public AccountCertificateInfo(String hostname, PrivateKey privateKey, List<Certificate> certificateChain)
    {
        setHostname(hostname);
        setPrivateKey(privateKey);
        setCertificateChain(certificateChain);
    }
    
    public String getHostname()
    {
        return hostname;
    }

    public void setHostname(String hostname)
    {
        this.hostname = hostname;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public List<Certificate> getCertificateChain()
    {
        return certificateChain;
    }

    public void setCertificateChain(List<Certificate> certificateChain)
    {
        this.certificateChain = certificateChain;
    }
}
