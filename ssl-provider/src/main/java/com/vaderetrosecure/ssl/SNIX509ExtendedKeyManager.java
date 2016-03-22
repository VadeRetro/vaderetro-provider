/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.DAOHelper;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;

/**
 * @author ahonore
 *
 */
public class SNIX509ExtendedKeyManager extends X509ExtendedKeyManager
{
    private final static Logger LOG = Logger.getLogger(SNIX509ExtendedKeyManager.class);

    private KeyStoreDAO keyStoreDAO;
    private KeyStoreMetaData keyStoreMetaData;
    private char[] masterPassword;

    SNIX509ExtendedKeyManager(KeyStoreDAO keyStoreDAO, KeyStoreMetaData keyStoreMetaData, char[] masterPassword)
    {
        super();
        this.keyStoreDAO = keyStoreDAO;
        this.keyStoreMetaData = keyStoreMetaData;
        this.masterPassword = masterPassword;
    }

    KeyStoreDAO getKeyStoreDAO()
    {
        return keyStoreDAO;
    }
    
    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias)
    {
		try
		{
			List<Certificate> entries = DAOHelper.getListOfCertificates(keyStoreDAO, alias);
	        if (entries.isEmpty())
	            return null;
	        
	        return entries.toArray(new X509Certificate[] {});
		}
		catch (KeyStoreDAOException | CertificateException e)
		{
			LOG.debug(e, e);
			LOG.error(e);
		}
        
        return null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public PrivateKey getPrivateKey(String alias)
    {
		try
		{
			return DAOHelper.getPrivateKey(keyStoreDAO, keyStoreMetaData, alias);
		}
		catch (KeyStoreDAOException | NoSuchAlgorithmException e)
		{
			LOG.debug(e, e);
			LOG.error(e);
		}
        
        return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        // TODO Auto-generated method stub
        return null;
    }

}
