/**
 * 
 */
package com.vaderetrosecure.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

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
//    private Cipher masterCipher;
//    private Cipher masterDecipher;
    
    public VRKeystoreSpi()
    {
        keystoreDAO = null;
//        masterCipher = null;
//        masterDecipher = null;
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
    
    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			List<KeyStoreEntry> entries = keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.PRIVATE_KEY);
			if (!entries.isEmpty())
				return entries.get(0) toArray(new Certificate[]{});
			entries = keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.SECRET_KEY);
			if (!entries.isEmpty())
				return entries.get(0) toArray(new Certificate[]{});
		}
        catch (IOException e)
        {
            LOG.error(e, e);
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
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<Certificate> certChain = new ArrayList<>();
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
				keystoreDAO.setKeyStoreEntry(new KeyStoreEntry(alias, KeyStoreEntryType.SECRET_KEY, 0, creationDate, key.getEncoded()));
			else
			{
				List<KeyStoreEntry> entries = new ArrayList<>();
				entries.add(new KeyStoreEntry(alias, KeyStoreEntryType.PRIVATE_KEY, 0, creationDate, key.getEncoded()));
				if (chain != null)
				{
					for (int i = 0 ; i < chain.length ; i++)
						entries.add(new KeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE, i, creationDate, chain[i].getEncoded()));
				}
				keystoreDAO.setKeyStoreEntries(entries);
			}
        }
        catch (VRKeyStoreDAOException | IOException | CertificateEncodingException e)
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
			keystoreDAO.setKeyStoreEntry(new KeyStoreEntry(alias, KeyStoreEntryType.KEY, 0, creationDate, key));
        }
        catch (VRKeyStoreDAOException | IOException e)
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
			KeyStoreEntry kse = new KeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE, 0, creationDate, cert.getEncoded());
			keystoreDAO.setKeyStoreEntry(kse);
        }
        catch (VRKeyStoreDAOException | IOException | CertificateEncodingException e)
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
            keystoreDAO.checkSchema();
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
            KeyStoreMetaData ksmd = keystoreDAO.getMetaData();
            ksmd.checkIntegrity(password);
        }
        catch (VRKeyStoreDAOException | GeneralSecurityException e)
        {
            LOG.error(e);
            throw new IOException(e);
        }
    }

    
    private void checkKeyStoreDAOIsLoaded() throws IOException
    {
        if (keystoreDAO != null)
        {
            final String errorMsg = "keystore dao is not loaded";
            LOG.fatal(errorMsg);
            throw new IOException(errorMsg);
        }
    }
}
