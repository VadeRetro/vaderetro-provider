/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;

/**
 * @author ahonore
 *
 */
public class SNIX509ExtendedKeyManager extends X509ExtendedKeyManager
{
    private static final Logger LOG = Logger.getLogger(SNIX509ExtendedKeyManager.class);

    private KeyStoreDAO keyStoreDAO;
    private PrivateKey privateKey;

    SNIX509ExtendedKeyManager(KeyStoreDAO keyStoreDAO, PrivateKey privateKey)
    {
        super();
        this.keyStoreDAO = keyStoreDAO;
        this.privateKey = privateKey;
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
        
        return getSelectedSNIAlias(keyType, engine.getSSLParameters().getSNIMatchers());
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
        
        return getSelectedSNIAlias(keyType, ((SSLSocket) socket).getSSLParameters().getSNIMatchers());
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias)
    {
        try
        {
            KeyStoreEntry kse = keyStoreDAO.getEntry(alias);
            if ((kse != null) && (kse.getEntryType() == KeyStoreEntryType.PRIVATE_KEY) && !kse.getCertificateChain().isEmpty())
            {
                List<X509Certificate> certs = new ArrayList<>();
                for (CertificateData ce : kse.getCertificateChain())
                    certs.add((X509Certificate) ce.getCertificate());
                
                return certs.toArray(new X509Certificate[] {});
            }
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
            KeyStoreEntry kse = keyStoreDAO.getEntry(alias);
            if (kse.getEntryType() == KeyStoreEntryType.PRIVATE_KEY)
            {
                KeyProtection kp = new KeyProtection(kse.getLockedKeyProtection(), privateKey);
                return (PrivateKey) kse.getKey(kp);
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
            List<String> aliases = keyStoreDAO.getAliases(keyType);
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

    private String getSelectedSNIAlias(String keyType, Collection<SNIMatcher> sniMatchers)
    {
        Collection<VRSNIMatcher> vrSniMatchers = sniMatchers.stream()
                .filter(m -> VRSNIMatcher.class.isInstance(m))
                .map(m -> (VRSNIMatcher) m)
                .collect(Collectors.toList());
        
        for (VRSNIMatcher m : vrSniMatchers)
        {
            for (KeyStoreEntry kse : m.getSelectedEntries())
            {
                String algo = kse.getAlgorithm();
                if ((algo != null) && algo.equalsIgnoreCase(keyType))
                    return kse.getAlias();
            }
        }
        
        return null;
    }
}
