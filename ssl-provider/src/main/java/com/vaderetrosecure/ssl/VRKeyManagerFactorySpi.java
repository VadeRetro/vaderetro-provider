/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

import org.apache.log4j.Logger;

import com.vaderetrosecure.VadeRetroProvider;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;

/**
 * @author ahonore
 *
 */
public class VRKeyManagerFactorySpi extends KeyManagerFactorySpi
{
    private static final Logger LOG = Logger.getLogger(VRKeyManagerFactorySpi.class);

	private KeyManager keyManagers[];
	
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
			KeyStoreMetaData keyStoreMetaData = ksdao.getMetaData();
			keyStoreMetaData.checkIntegrity(password);
	    	keyManagers = new KeyManager[] { new SNIX509ExtendedKeyManager(ksdao, keyStoreMetaData) };
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
}
