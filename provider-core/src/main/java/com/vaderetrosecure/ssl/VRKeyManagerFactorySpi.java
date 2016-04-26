/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

import org.apache.log4j.Logger;

import com.vaderetrosecure.VadeRetroProvider;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;

/**
 * The KeyManager of the Vade Retro Provider.
 * This key manager is backed by a DAO, so a DAO implementation must be provided for this class to work.
 * To use it:
 * <pre>
 * <code>
 * KeyStore ks = KeyStore.getInstance("KS", VadeRetroProvider.VR_PROVIDER);
 * KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509", VadeRetroProvider.VR_PROVIDER);
 * kmf.init(ks, null);</code></pre>
 * If stored password protections were ciphered with a public key from {@link com.vaderetrosecure.keystore.VRKeyStoreSpi}, 
 * they are deciphered with a private key. Just add the file {@code com.vaderetrosecure.key.private}, containing 
 * a private key in the PKCS8 DER format. The private key must be at least 2048-bit long.
 * 
 * @see com.vaderetrosecure.keystore.dao.KeyStoreDAO
 * @see com.vaderetrosecure.keystore.VRKeyStoreSpi
 */
public class VRKeyManagerFactorySpi extends KeyManagerFactorySpi
{
    private static final Logger LOG = Logger.getLogger(VRKeyManagerFactorySpi.class);

    private static final String VR_KEYSTORE_PRIVATE_KEY_FILE = "com.vaderetrosecure.key.private";

    private KeyManager[] keyManagers;
    
    public VRKeyManagerFactorySpi()
    {
        keyManagers = null;
    }

    @Override
    protected KeyManager[] engineGetKeyManagers()
    {
        if (keyManagers == null)
            throw new IllegalStateException();
        
        return keyManagers;
    }

    /**
     * Not implemented.
     * Throw an UnsupportedOperationException exception.
     * 
     * {@inheritDoc}
     * 
     * @see javax.net.ssl.KeyManagerFactorySpi#engineInit(javax.net.ssl.ManagerFactoryParameters)
     */
    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if ((ks == null) || (!ks.getProvider().getName().equals(VadeRetroProvider.VR_PROVIDER)))
        {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password);
            keyManagers = kmf.getKeyManagers();
        }
        
        try
        {
            KeyStoreDAO ksdao = KeyStoreDAOFactory.getInstance().getKeyStoreDAO();
            
            IntegrityData integrityData = ksdao.getIntegrityData();
            if (password != null)
                integrityData.checkIntegrity(password);
            keyManagers = new KeyManager[] { new SNIX509ExtendedKeyManager(ksdao, loadKeyProtectionPrivateKey()) };
        }
        catch (KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
            throw new KeyStoreException(e);
        }
        catch (InvalidKeySpecException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
            throw new UnrecoverableKeyException();
        }
        catch (IOException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
            throw new KeyStoreException(e);
        }
    }
    
    private PrivateKey loadKeyProtectionPrivateKey()
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
            LOG.warn("private key not found: if a public key was used, unprotecting will throw errors", e);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            LOG.debug(e, e);
            LOG.warn("bad private key format: if a public key was used, unprotecting will throw errors", e);
        }

        return null;
    }
}
