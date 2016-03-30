/**
 * 
 */
package com.vaderetrosecure.keystore;

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
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
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

import com.vaderetrosecure.keystore.dao.CipheringTools;
import com.vaderetrosecure.keystore.dao.DAOHelper;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyEntry;
import com.vaderetrosecure.keystore.dao.KeyEntryType;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class VRKeyStoreSpi extends KeyStoreSpi
{
    private final static Logger LOG = Logger.getLogger(VRKeyStoreSpi.class);

    private KeyStoreDAO keystoreDAO;
    private IntegrityData integrityData;
    private SecretKey masterKey;
    
    public VRKeyStoreSpi()
    {
        keystoreDAO = null;
        integrityData = null;
        masterKey = null;

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
        integrityData = null;
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
			
			KeyProtection kp = keystoreDAO.getKeyProtection(alias);
			if (kp == null)
			{
				final String msg = "KeyProtection not found";
	            LOG.error(msg);
	            throw new UnrecoverableKeyException(msg);
			}

			SecretKey keyPass = CipheringTools.getAESSecretKey(password, integrityData.getKeyPasswordSalt(masterKey));
			
//			PrivateKey pk = DAOHelper.getPrivateKey(keystoreDAO, integrityData, alias);
//			if (pk != null)
//			    return pk;

			List<KeyEntry> entries = keystoreDAO.getKeyEntry(alias, KeyEntryType.PRIVATE_KEY);
			if (!entries.isEmpty())
			{
			    KeyEntry kse = entries.get(0);
		        KeyFactory kf = KeyFactory.getInstance(kse.getAlgorithm());
		            return kf.generatePrivate(new PKCS8EncodedKeySpec(keyStoreMetaData.decipherKeyEntry(null, kse.getData())));
			}

			List<KeyEntry> entries = keystoreDAO.getKeyEntry(alias, KeyEntryType.SECRET_KEY);
            if (!entries.isEmpty())
            {
                KeyEntry kse = entries.get(0);
                return new SecretKeySpec(integrityData.decipherKeyEntry(null, kse.getData()), kse.getAlgorithm());
            }

            return null;
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

            List<Certificate> certChain = Collections.emptyList();
            certChain = DAOHelper.getListOfCertificates(keystoreDAO, alias);
	        if (certChain.isEmpty())
	            return null;
	        
	        return certChain.toArray(new Certificate[]{});
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

            List<Certificate> certChain = Collections.emptyList();
            certChain = DAOHelper.getListOfCertificates(keystoreDAO, alias);
            
            if (certChain.isEmpty())
                return null;
            
            return certChain.get(0);
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

			List<KeyEntry> entries = keystoreDAO.getKeyEntry(alias);
            if (entries.isEmpty())
                return null;
            
            return entries.get(0).getCreationDate();
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

			Date creationDate = Date.from(Instant.now());
			if (SecretKey.class.isInstance(key))
				keystoreDAO.setKeyEntries(Collections.singleton(new KeyEntry(alias, KeyEntryType.SECRET_KEY, 0, creationDate, key.getAlgorithm(), integrityData.cipherKeyEntry(null, key.getEncoded()))));
			else
			{
				List<KeyEntry> entries = new ArrayList<>();
				entries.add(new KeyEntry(alias, KeyEntryType.PRIVATE_KEY, 0, creationDate, key.getAlgorithm(), integrityData.cipherKeyEntry(null, key.getEncoded())));
				if (chain != null)
				{
					for (int i = 0 ; i < chain.length ; i++)
						entries.add(new KeyEntry(alias, KeyEntryType.CERTIFICATE, i, creationDate, chain[i].getPublicKey().getAlgorithm(), chain[i].getEncoded(), getCertificateNames(chain[i])));
				}
                keystoreDAO.setKeyEntries(entries);
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

			Date creationDate = Date.from(Instant.now());
			List<KeyEntry> entries = new ArrayList<>();
			entries.add(new KeyEntry(alias, KeyEntryType.KEY, 0, creationDate, null, key));
            if (chain != null)
            {
                for (int i = 0 ; i < chain.length ; i++)
                    entries.add(new KeyEntry(alias, KeyEntryType.CERTIFICATE, i, creationDate, chain[i].getPublicKey().getAlgorithm(), chain[i].getEncoded(), getCertificateNames(chain[i])));
            }
            keystoreDAO.setKeyEntries(entries);
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
			KeyEntry kse = new KeyEntry(alias, KeyEntryType.CERTIFICATE, 0, creationDate, cert.getPublicKey().getAlgorithm(), cert.getEncoded(), getCertificateNames(cert));
			keystoreDAO.setKeyEntries(Collections.singleton(kse));
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

			keystoreDAO.deleteEntries(Collections.singleton(alias));
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

			return !keystoreDAO.getKeyEntry(alias).isEmpty();
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
			
            return !keystoreDAO.getKeyEntry(alias, KeyEntryType.SECRET_KEY).isEmpty() || 
            		!keystoreDAO.getKeyEntry(alias, KeyEntryType.PRIVATE_KEY).isEmpty() ||
            		!keystoreDAO.getKeyEntry(alias, KeyEntryType.KEY).isEmpty();
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

			return !keystoreDAO.getKeyEntry(alias, KeyEntryType.CERTIFICATE).isEmpty();
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
        
//        try
//        {
//            keystoreDAO.createSchema();
//            KeyStoreMetaData ksmd = KeyStoreMetaData.generate(password);
//            keystoreDAO.setMetaData(ksmd);
//        }
//        catch (VRKeyStoreDAOException | UnrecoverableKeyException e)
//        {
//            LOG.error(e, e);
//            throw new IOException(e);
//        }
//        catch (GeneralSecurityException e)
//        {
//            LOG.error(e, e);
//            throw new NoSuchAlgorithmException(e);
//        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        checkKeyStoreDAOIsLoaded();
        
        try
        {
            integrityData = keystoreDAO.getIntegrityData();
        }
        catch (KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.info(e);
            try
            {
                keystoreDAO.checkDAOStructure();
                integrityData = IntegrityData.generate(password);
                keystoreDAO.setIntegrityData(integrityData);
            }
            catch (GeneralSecurityException | KeyStoreDAOException ee)
            {
                LOG.debug(ee, ee);
                LOG.fatal(ee);
                throw new NoSuchAlgorithmException(ee);
            }
        }

        try
        {
            masterKey = integrityData.getMasterKey(password);
            integrityData.checkIntegrity(masterKey);
        }
        catch (UnrecoverableKeyException | InvalidKeySpecException e)
        {
            LOG.debug(e, e);
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
