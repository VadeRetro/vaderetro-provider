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
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

import org.apache.log4j.Logger;

import com.vaderetrosecure.VadeRetroProvider;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class VRKeyManagerFactorySpi extends KeyManagerFactorySpi
{
    private static final Logger LOG = Logger.getLogger(VRKeyManagerFactorySpi.class);

    private final static String VR_KEYSTORE_PUBLIC_KEY_FILE = "com.vaderetrosecure.key.public";

	private KeyManager keyManagers[];
	private PublicKey publicKey;
	
	public VRKeyManagerFactorySpi()
	{
	    keyManagers = null;
	    publicKey = null;
	}

    @Override
    protected KeyManager[] engineGetKeyManagers()
    {
    	if (keyManagers == null)
    		throw new IllegalStateException();
    	
        return keyManagers;
    }

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
			
			if (publicKey == null)
			    publicKey = loadPublicKeyProtection();
			
			IntegrityData integrityData = ksdao.getIntegrityData();
			if (password != null)
			    integrityData.checkIntegrity(password);
	    	keyManagers = new KeyManager[] { new SNIX509ExtendedKeyManager(ksdao, integrityData) };
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
    
    
    private PublicKey loadPublicKeyProtection()
    {
        URL url = Thread.currentThread().getContextClassLoader().getResource(VR_KEYSTORE_PUBLIC_KEY_FILE);
        if (url == null)
            return null;

        try
        {
            byte[] encKey = Files.readAllBytes(Paths.get(url.toURI()));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new X509EncodedKeySpec(encKey));
        }
        catch (IOException | URISyntaxException e)
        {
            LOG.debug(e, e);
            LOG.warn("public key not found: if a private key was used, unprotecting will throw errors", e);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            LOG.debug(e, e);
            LOG.warn("bad public key format: if a private key was used, unprotecting will throw errors", e);
        }

        return null;
    }
}
