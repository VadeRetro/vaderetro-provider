/**
 * 
 */
package com.vaderetrosecure.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.naming.InvalidNameException;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.CertificatesEntry;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyEntry;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;
import com.vaderetrosecure.keystore.dao.LockedKeyProtection;
import com.vaderetrosecure.keystore.dao.PrivateKeyEntry;
import com.vaderetrosecure.keystore.dao.SecretKeyEntry;

/**
 * @author ahonore
 *
 */
public class VRKeyStoreSpi extends KeyStoreSpi
{
    private final static Logger LOG = Logger.getLogger(VRKeyStoreSpi.class);

    private final static String VR_KEYSTORE_PRIVATE_KEY_FILE = "com.vaderetrosecure.key.private";

    private KeyStoreDAO keystoreDAO;
    private PrivateKey privateKey;
    
    public VRKeyStoreSpi()
    {
        keystoreDAO = null;
        privateKey = null;

        try
        {
            KeyStoreDAOFactory ksFactory = KeyStoreDAOFactory.getInstance();
            keystoreDAO = ksFactory.getKeyStoreDAO();
        }
        catch (KeyStoreDAOException e)
        {
            LOG.fatal(e, e);
        }
    }

    VRKeyStoreSpi(KeyStoreDAO keystoreDAO)
    {
        this.keystoreDAO = keystoreDAO;
        this.privateKey = null;
    }
    
    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			KeyEntry ke = keystoreDAO.getKeyEntry(alias);
			if (ke == null)
				return null;

			IntegrityData id = keystoreDAO.getIntegrityData();
			if (id == null)
			{
				final String msg = "IntegrityData not found";
	            LOG.error(msg);
	            throw new UnrecoverableKeyException(msg);
			}
			
			LockedKeyProtection lkp = ke.getLockedKeyProtection();
			if (lkp == null)
			{
				final String msg = "KeyProtection not found";
	            LOG.error(msg);
	            throw new UnrecoverableKeyException(msg);
			}

			KeyProtection kp = KeyProtection.generateKeyProtection(password, id.getSalt(), lkp.getIV());
			
			return ke.getKey(kp);
		}
        catch (IOException | KeyStoreDAOException e)
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

			CertificatesEntry certChain = keystoreDAO.getCertificatesEntry(alias);
			if (certChain != null)
			{
    	        List<Certificate> certs = new ArrayList<>();
    	        for (CertificateData cd : certChain.getCertificates())
                    certs.add(cd.getCertificate());
    	        
    	        return certs.toArray(new Certificate[]{});
			}
		}
        catch (CertificateException | KeyStoreDAOException | IOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
		}
        
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        try
        {
			checkKeyStoreDAOIsLoaded();

			CertificatesEntry cert = keystoreDAO.getCertificatesEntry(alias);
            if (cert != null)
                return cert.getCertificates().get(0).getCertificate();
		}
        catch (CertificateException | KeyStoreDAOException | IOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }

        return null;
    }
    
    @Override
    public Date engineGetCreationDate(String alias)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

	         KeyEntry ke = keystoreDAO.getKeyEntry(alias);
	         if (ke != null)
	             return ke.getCreationDate();

	         CertificatesEntry ce = keystoreDAO.getCertificatesEntry(alias);
	         if (ce != null)
	             return ce.getCreationDate();
        }
        catch (KeyStoreDAOException e)
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

            IntegrityData id = keystoreDAO.getIntegrityData();
            if (id == null)
            {
                final String msg = "IntegrityData not found";
                LOG.error(msg);
                throw new KeyStoreException(msg);
            }

            Date creationDate = Date.from(Instant.now());
            
            KeyProtection kp = KeyProtection.generateKeyProtection(password, id.getSalt());
            
            KeyEntry ke = null;
            if (SecretKey.class.isInstance(key))
                ke = new SecretKeyEntry(alias, creationDate, (SecretKey) key, kp);
            else if (PrivateKey.class.isInstance(key))
                ke = new PrivateKeyEntry(alias, creationDate, (PrivateKey) key, kp);
            else
                ke = new KeyEntry(alias, creationDate, key.getAlgorithm(), key.getEncoded(), null);
			
            ke.setLockedKeyProtection(kp.getLockedKeyProtection(privateKey));
            
            keystoreDAO.setEntry(ke);
            
            if ((chain != null) && (chain.length > 0))
            {
                List<CertificateData> certsData = new ArrayList<>();
                for (Certificate c : chain)
                    certsData.add(new CertificateData(c));
                
                keystoreDAO.setEntry(new CertificatesEntry(alias, creationDate, certsData));
            }
        }
        catch (KeyStoreDAOException | IOException | CertificateEncodingException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | CertificateParsingException | InvalidNameException e)
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

            IntegrityData id = keystoreDAO.getIntegrityData();
            if (id == null)
            {
                final String msg = "IntegrityData not found";
                LOG.error(msg);
                throw new KeyStoreException(msg);
            }

            Date creationDate = Date.from(Instant.now());
            
            keystoreDAO.setEntry(new KeyEntry(alias, creationDate, null, key, null));

            if ((chain != null) && (chain.length > 0))
            {
                
                List<CertificateData> certsData = new ArrayList<>();
                for (Certificate c : chain)
                    certsData.add(new CertificateData(c));
                
                keystoreDAO.setEntry(new CertificatesEntry(alias, creationDate, certsData));
            }
        }
        catch (KeyStoreDAOException | IOException | CertificateEncodingException | CertificateParsingException | InvalidNameException e)
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
			CertificatesEntry ce = new CertificatesEntry(alias, creationDate, Collections.singletonList(new CertificateData(cert)));
			keystoreDAO.setEntry(ce);
        }
        catch (KeyStoreDAOException | IOException | CertificateEncodingException | CertificateParsingException | InvalidNameException e)
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

			keystoreDAO.deleteKeyEntry(alias);
			keystoreDAO.deleteCertificatesEntry(alias);
        }
        catch (KeyStoreDAOException e)
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
        catch (KeyStoreDAOException e)
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

			return (keystoreDAO.getKeyEntry(alias) != null) || (keystoreDAO.getCertificatesEntry(alias) != null);
        }
        catch (KeyStoreDAOException e)
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
        catch (KeyStoreDAOException e)
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
			
            return keystoreDAO.getKeyEntry(alias) != null;
        }
        catch (KeyStoreDAOException e)
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

			return keystoreDAO.getCertificatesEntry(alias) != null;
        }
        catch (KeyStoreDAOException e)
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
            keystoreDAO.checkDAOStructure();
            IntegrityData id = keystoreDAO.getIntegrityData();
            id = new IntegrityData(id.getSalt(), password);
            keystoreDAO.setIntegrityData(id);
        }
        catch (NullPointerException | KeyStoreDAOException e)
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
            keystoreDAO.checkDAOStructure();
            IntegrityData id = keystoreDAO.getIntegrityData();
            if (id == null)
            {
                id = new IntegrityData(password);
                keystoreDAO.setIntegrityData(id);
            }
            
            if (privateKey == null)
                privateKey = loadPrivateKeyProtection();
            
            if (password != null)
                id.checkIntegrity(password);
        }
        catch (UnrecoverableKeyException | InvalidKeySpecException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new IOException(e);
        }
        catch (GeneralSecurityException | KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
            throw new NoSuchAlgorithmException(e);
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
    
    private PrivateKey loadPrivateKeyProtection()
    {
        URL url = Thread.currentThread().getContextClassLoader().getResource(VR_KEYSTORE_PRIVATE_KEY_FILE);
        if (url == null)
            return null;

        try
        {
            byte[] encKey = Files.readAllBytes(Paths.get(url.toURI()));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(encKey));
        }
        catch (IOException | URISyntaxException e)
        {
            LOG.debug(e, e);
            LOG.warn("private key not found: keystore will not be protected", e);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            LOG.debug(e, e);
            LOG.warn("bad private key format: keystore will not be protected", e);
        }

        return null;
    }
}
