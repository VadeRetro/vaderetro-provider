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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
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
public class CertificateEntry
{
    private final static Logger LOG = Logger.getLogger(CertificateEntry.class);

    private String alias;
    private int rank;
    private Date creationDate;
    private String algorithm;
    private byte[] encodedCertificate;
    private List<String> names;

    public CertificateEntry()
    {
        this("", 0, Date.from(Instant.now()), "", new byte[]{}, new ArrayList<>());
    }

    public CertificateEntry(String alias, int rank, Date creationDate, String algorithm, byte[] encodedCertificate, List<String> names)
    {
        this.alias = alias;
        this.rank = rank;
        this.creationDate = creationDate;
        this.algorithm = algorithm;
        this.encodedCertificate = encodedCertificate;
        this.names = names;
    }

    public CertificateEntry(String alias, int rank, Date creationDate, Certificate certificate)
    {
        this.alias = alias;
        this.rank = rank;
        this.creationDate = creationDate;
        if (certificate == null)
        {
            this.algorithm = "";
            this.encodedCertificate = new byte[]{};
            this.names = new ArrayList<>();
        }
        else
        {
            this.algorithm = certificate.getPublicKey().getAlgorithm();
            try
            {
                this.encodedCertificate = certificate.getEncoded();
                this.names = extractCertificateNames(certificate);
            }
            catch (CertificateEncodingException | CertificateParsingException | InvalidNameException e)
            {
                LOG.debug(e, e);
                LOG.error(e);
                
                this.algorithm = "";
                this.encodedCertificate = new byte[]{};
                this.names = new ArrayList<>();
            }
        }
    }
    
    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public int getRank()
    {
        return rank;
    }

    public void setRank(int rank)
    {
        this.rank = rank;
    }

    public Date getCreationDate()
    {
        return creationDate;
    }

    public void setCreationDate(Date creationDate)
    {
        this.creationDate = creationDate;
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

    public List<String> getNames()
    {
        return names;
    }

    public void setNames(List<String> names)
    {
        this.names = names;
    }
    
    private List<String> extractCertificateNames(Certificate cert) throws InvalidNameException, CertificateParsingException
    {
        if (!X509Certificate.class.isInstance(cert))
            return new ArrayList<>();
        
        Set<String> hosts = new HashSet<>();
        X509Certificate x509 = (X509Certificate) cert;
        String dn = x509.getSubjectX500Principal().getName();
        LdapName ldapDN = new LdapName(dn);
        for(Rdn rdn: ldapDN.getRdns())
            if (rdn.getType().equalsIgnoreCase("CN"))
                hosts.add((String) rdn.getValue());

        Collection<List<?>> altList = x509.getSubjectAlternativeNames();
        if (altList != null)
            for (List<?> alt : altList)
                if (((Integer) alt.get(0)).intValue() == 2) // 2 is a SubjectALT DNS name
                    hosts.add((String) alt.get(1));
        
        return new ArrayList<>(hosts);
    }
}
