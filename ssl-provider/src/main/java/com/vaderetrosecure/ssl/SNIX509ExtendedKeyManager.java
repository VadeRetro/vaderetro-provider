/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.DAOHelper;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyEntry;
import com.vaderetrosecure.keystore.dao.IntegrityData;

/**
 * @author ahonore
 *
 */
public class SNIX509ExtendedKeyManager extends X509ExtendedKeyManager
{
    private final static Logger LOG = Logger.getLogger(SNIX509ExtendedKeyManager.class);

    private KeyStoreDAO keyStoreDAO;
    private IntegrityData keyStoreMetaData;

    SNIX509ExtendedKeyManager(KeyStoreDAO keyStoreDAO, IntegrityData keyStoreMetaData)
    {
        super();
        this.keyStoreDAO = keyStoreDAO;
        this.keyStoreMetaData = keyStoreMetaData;
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
        String[] aliases = getServerAliases(keyType, issuers);
        if (aliases == null)
            return null;
        
        return getSelectedSNIAlias(keyType, issuers, engine.getSSLParameters().getSNIMatchers());
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        String[] aliases = getServerAliases(keyType, issuers);
        if (aliases == null)
            return null;
        
        return getSelectedSNIAlias(keyType, issuers, ((SSLSocket) socket).getSSLParameters().getSNIMatchers());
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
        try
        {
            List<String> aliases = keyStoreDAO.getAuthenticationAliases(keyType);
            if (aliases.isEmpty())
                return null;
            
            return aliases.toArray(new String[] {});
        }
        catch (KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }

        return null;
    }

    private String getSelectedSNIAlias(String keyType, Principal[] issuers, Collection<SNIMatcher> sniMatchers)
    {
        for (SNIMatcher m : sniMatchers)
        {
            if (VRSNIMatcher.class.isInstance(m))
                for (KeyEntry kse : ((VRSNIMatcher) m).getSelectedEntries())
                    if (kse.getAlgorithm().equals(keyType))
                        return kse.getAlias();
        }
        
        return null;
    }
}
