/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.CertificatesEntry;
import com.vaderetrosecure.keystore.dao.KeyEntry;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.PrivateKeyEntry;

/**
 * @author ahonore
 *
 */
public class SNIX509ExtendedKeyManager extends X509ExtendedKeyManager
{
    private final static Logger LOG = Logger.getLogger(SNIX509ExtendedKeyManager.class);

    private KeyStoreDAO keyStoreDAO;
    private PublicKey publicKey;

    SNIX509ExtendedKeyManager(KeyStoreDAO keyStoreDAO, PublicKey publicKey)
    {
        super();
        this.keyStoreDAO = keyStoreDAO;
        this.publicKey = publicKey;
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
			CertificatesEntry ce = keyStoreDAO.getCertificatesEntry(alias);
	        if (ce != null)
	        {
	            List<X509Certificate> certs = new ArrayList<>();
	            for (CertificateData cd : ce.getCertificates())
	                certs.add((X509Certificate) cd.getCertificate());
	            
	            return certs.toArray(new X509Certificate[] {});
	        }
		}
		catch (KeyStoreDAOException | CertificateException | IOException e)
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
		    KeyEntry ke = keyStoreDAO.getKeyEntry(alias);
		    if (PrivateKeyEntry.class.isInstance(ke))
		    {
		        KeyProtection kp = new KeyProtection(ke.getLockedKeyProtection(), publicKey);
		        return (PrivateKey) ke.getKey(kp);
		    }
		}
		catch (KeyStoreDAOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException e)
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
                for (CertificatesEntry ce : ((VRSNIMatcher) m).getSelectedEntries())
                    if (ce.getCertificates().get(0).getAlgorithm().equals(keyType))
                        return ce.getAlias();
        }
        
        return null;
    }
}
