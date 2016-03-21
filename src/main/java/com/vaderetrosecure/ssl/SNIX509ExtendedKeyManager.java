/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.net.Socket;
import java.security.KeyFactory;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;

/**
 * @author ahonore
 *
 */
public class SNIX509ExtendedKeyManager extends X509ExtendedKeyManager
{
    private final static Logger LOG = Logger.getLogger(SNIX509ExtendedKeyManager.class);

    private KeyStoreDAO keyStoreDAO;
    private char[] masterPassword;

    SNIX509ExtendedKeyManager(KeyStoreDAO keyStoreDAO, char[] masterPassword)
    {
        super();
        this.keyStoreDAO = keyStoreDAO;
        this.masterPassword = masterPassword;
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
        // TODO Auto-generated method stub
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
        List<KeyStoreEntry> entries = keyStoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.PRIVATE_KEY);
        if (entries.isEmpty())
            return null;
        
        KeyStoreEntry kse = entries.get(0);
        KeyFactory kf = KeyFactory.getInstance(kse.getAlgorithm());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(keyStoreMetaData.decipherKeyEntry(password, kse.getData())));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        // TODO Auto-generated method stub
        return null;
    }

}
