/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.log4j.Logger;

/**
 * @author ahonore
 *
 */
public class CertificateData
{
    private final static Logger LOG = Logger.getLogger(CertificateData.class);

    private String algorithm;
    private byte[] encodedCertificate;
    private Set<String> names;

    public CertificateData()
    {
        this(null, new byte[]{}, new HashSet<>());
    }

    public CertificateData(String algorithm, byte[] encodedCertificate, Set<String> names)
    {
        this.algorithm = algorithm;
        this.encodedCertificate = encodedCertificate;
        this.names = names;
    }

    public CertificateData(Certificate certificate) throws CertificateEncodingException, CertificateParsingException, InvalidNameException
    {
        this();
        if (certificate != null)
        {
            this.algorithm = certificate.getPublicKey().getAlgorithm();
            this.encodedCertificate = certificate.getEncoded();
            this.names = extractCertificateNames(certificate);
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
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
        try (InputStream is = new ByteArrayInputStream(getEncodedCertificate()))
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificate(is);
        }
    }

    public Set<String> getNames()
    {
        return names;
    }

    public void setNames(Set<String> names)
    {
        this.names = names;
    }
    
    private Set<String> extractCertificateNames(Certificate cert) throws InvalidNameException, CertificateParsingException
    {
        Set<String> hosts = new HashSet<>();

        if (!X509Certificate.class.isInstance(cert))
            return hosts;
        
        X509Certificate x509 = (X509Certificate) cert;
        String dn = x509.getSubjectX500Principal().getName();
        LdapName ldapDN = new LdapName(dn);
        for(Rdn rdn: ldapDN.getRdns())
            if (rdn.getType().equalsIgnoreCase("CN"))
            {
                String host = (String) rdn.getValue();
                LOG.debug("CN: " + host);
                hosts.add(host);
            }

        Collection<List<?>> altList = x509.getSubjectAlternativeNames();
        if (altList != null)
            for (List<?> alt : altList)
                if (((Integer) alt.get(0)).intValue() == 2) // 2 is a SubjectALT DNS name
                {
                    String host = (String) alt.get(1);
                    LOG.debug("alt DNS: " + host);
                    hosts.add(host);
                }
        
        return hosts;
    }
}
