/**
 * 
 */
package com.vaderetrosecure.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.CertificateName;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class VRKeystoreSpi extends KeyStoreSpi
{
    private final static Logger LOG = Logger.getLogger(VRKeystoreSpi.class);

    private VRKeyStoreDAO keystoreDAO;
    private KeyStoreMetaData keyStoreMetaData;
    
    public VRKeystoreSpi()
    {
        keystoreDAO = null;
        keyStoreMetaData = null;

        try
        {
            VRKeyStoreDAOFactory ksFactory = VRKeyStoreDAOFactory.getInstance();
            keystoreDAO = ksFactory.getKeyStoreDAO();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.fatal(e, e);
        }
    }

    VRKeystoreSpi(VRKeyStoreDAO keystoreDAO)
    {
        this.keystoreDAO = keystoreDAO;
        keyStoreMetaData = null;
    }
    
    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			List<KeyStoreEntry> entries = keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.PRIVATE_KEY);
			if (!entries.isEmpty())
			{
			    KeyStoreEntry kse = entries.get(0);
			    KeyFactory kf = KeyFactory.getInstance(kse.getAlgorithm());
			    return kf.generatePrivate(new PKCS8EncodedKeySpec(keyStoreMetaData.decipherKey(password, kse.getData())));
			}
			
            entries = keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.SECRET_KEY);
            if (!entries.isEmpty())
            {
                KeyStoreEntry kse = entries.get(0);
                return new SecretKeySpec(keyStoreMetaData.decipherKey(password, kse.getData()), kse.getAlgorithm());
            }

            return null;
		}
        catch (IOException | VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
		}
        catch (InvalidKeySpecException e)
        {
            LOG.error(e, e);
            throw new NoSuchAlgorithmException(e);
        }
        catch (InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            LOG.error(e, e);
            throw new UnrecoverableKeyException("wrong key password");
        }
        
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

	        List<Certificate> certChain = getListOfCertificates(alias);
	        if (certChain.isEmpty())
	            return null;
	        
	        return certChain.toArray(new Certificate[]{});
		}
        catch (IOException e)
        {
            LOG.error(e, e);
		}
        
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			List<Certificate> certChain = getListOfCertificates(alias);
	        if (certChain.isEmpty())
	            return null;
	        
	        return certChain.get(0);
		}
        catch (IOException e)
        {
            LOG.error(e, e);
		}

        return null;
    }

    private List<Certificate> getListOfCertificates(String alias)
    {
        try
        {
            List<KeyStoreEntry> entries = keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE);
            if (entries.isEmpty())
                return Collections.emptyList();
            
            List<Certificate> certChain = new ArrayList<>();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (KeyStoreEntry kse : entries)
            {
                try (InputStream is = new ByteArrayInputStream(kse.getData()))
                {
                    Certificate cert = cf.generateCertificate(is);
                    certChain.add(cert);
                }
                catch (IOException e)
                {
                    LOG.error(e, e);
                }
            }
            
            return certChain;
        }
        catch (VRKeyStoreDAOException | CertificateException e)
        {
            LOG.error(e, e);
        }
        
        return Collections.emptyList();
    }
    
    @Override
    public Date engineGetCreationDate(String alias)
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			List<KeyStoreEntry> entries = keystoreDAO.getKeyStoreEntry(alias);
            if (entries.isEmpty())
                return null;
            
            return entries.get(0).getCreationDate();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
		}
        
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			Date creationDate = Date.from(Instant.now());
			if (SecretKey.class.isInstance(key))
				keystoreDAO.setKeyStoreEntries(Collections.singleton(new KeyStoreEntry(alias, KeyStoreEntryType.SECRET_KEY, 0, creationDate, key.getAlgorithm(), keyStoreMetaData.cipherKey(password, key.getEncoded()))));
			else
			{
				List<KeyStoreEntry> entries = new ArrayList<>();
				entries.add(new KeyStoreEntry(alias, KeyStoreEntryType.PRIVATE_KEY, 0, creationDate, key.getAlgorithm(), keyStoreMetaData.cipherKey(password, key.getEncoded()), Collections.emptyList()));
				if (chain != null)
				{
					for (int i = 0 ; i < chain.length ; i++)
					{
					    List<CertificateName> certNames = new ArrayList<>();
					    for (String name : getCertificateNames(chain[i]))
					        certNames.add(new CertificateName(name, alias, i));
						entries.add(new KeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE, i, creationDate, chain[i].getPublicKey().getAlgorithm(), chain[i].getEncoded(), certNames));
					}
				}
				keystoreDAO.setKeyStoreEntries(entries);
			}
        }
        catch (VRKeyStoreDAOException | IOException | CertificateEncodingException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | CertificateParsingException | InvalidNameException e)
        {
            LOG.error(e, e);
            throw new KeyStoreException(e);
        }
    }
    
    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			Date creationDate = Date.from(Instant.now());
			List<KeyStoreEntry> entries = new ArrayList<>();
			entries.add(new KeyStoreEntry(alias, KeyStoreEntryType.KEY, 0, creationDate, null, key));
            if (chain != null)
            {
                for (int i = 0 ; i < chain.length ; i++)
                {
                    List<CertificateName> certNames = new ArrayList<>();
                    for (String name : getCertificateNames(chain[i]))
                        certNames.add(new CertificateName(name, alias, i));
                    entries.add(new KeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE, i, creationDate, chain[i].getPublicKey().getAlgorithm(), chain[i].getEncoded(), certNames));
                }
            }
            keystoreDAO.setKeyStoreEntries(entries);
        }
        catch (VRKeyStoreDAOException | IOException | CertificateEncodingException | CertificateParsingException | InvalidNameException e)
        {
            LOG.error(e, e);
            throw new KeyStoreException(e);
        }
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			Date creationDate = Date.from(Instant.now());
			List<CertificateName> certNames = new ArrayList<>();
			for (String name : getCertificateNames(cert))
			    certNames.add(new CertificateName(name, alias, 0));
			KeyStoreEntry kse = new KeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE, 0, creationDate, cert.getPublicKey().getAlgorithm(), cert.getEncoded(), certNames);
			keystoreDAO.setKeyStoreEntries(Collections.singleton(kse));
        }
        catch (VRKeyStoreDAOException | IOException | CertificateEncodingException | CertificateParsingException | InvalidNameException e)
        {
            LOG.error(e, e);
            throw new KeyStoreException(e);
        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			keystoreDAO.deleteKeyStoreEntry(alias);
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
		}
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			List<String> aliases = keystoreDAO.getAliases();
            if (aliases.isEmpty())
                return Collections.emptyEnumeration();
            
            return Collections.enumeration(aliases);
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
		}

        return Collections.emptyEnumeration();
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			return !keystoreDAO.getKeyStoreEntry(alias).isEmpty();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
		}

        return false;
    }

    @Override
    public int engineSize()
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			return keystoreDAO.countEntries();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
		}

        return 0;
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        try
        {
			checkKeyStoreDAOIsLoaded();
			
            return !keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.SECRET_KEY).isEmpty() || 
            		!keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.PRIVATE_KEY).isEmpty() ||
            		!keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.KEY).isEmpty();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
		}

        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			return !keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE).isEmpty();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
		}

        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        LOG.warn("engineGetCertificateAlias: not yet implemented");
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        checkKeyStoreDAOIsLoaded();
        
        try
        {
            keystoreDAO.createSchema();
            KeyStoreMetaData ksmd = KeyStoreMetaData.generate(password);
            keystoreDAO.setMetaData(ksmd);
        }
        catch (VRKeyStoreDAOException | UnrecoverableKeyException e)
        {
            LOG.error(e, e);
            throw new IOException(e);
        }
        catch (GeneralSecurityException e)
        {
            LOG.error(e, e);
            throw new NoSuchAlgorithmException(e);
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        checkKeyStoreDAOIsLoaded();
        
        try
        {
            keyStoreMetaData = keystoreDAO.getMetaData();
            keyStoreMetaData.checkIntegrity(password);
        }
        catch (VRKeyStoreDAOException | GeneralSecurityException e)
        {
            LOG.error(e);
            throw new IOException(e);
        }
    }

    
    private void checkKeyStoreDAOIsLoaded() throws IOException
    {
        if (keystoreDAO == null)
        {
            final String errorMsg = "keystore dao is not loaded";
            LOG.fatal(errorMsg);
            throw new IOException(errorMsg);
        }
    }
    
    private List<String> getCertificateNames(Certificate cert) throws InvalidNameException, CertificateParsingException
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
