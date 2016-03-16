/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;

/**
 * @author ahonore
 *
 */
public class VRKeyStoreDAOX509KeyManager extends VRSNIX509ExtendedKeyManager
{
    private final static Logger LOG = Logger.getLogger(VRKeyStoreDAOX509KeyManager.class);

    private final VRKeyStoreDAO keyStoreDAO;
    private VRSNIMatcher sniMatcher;
    private X509ExtendedKeyManager keyManager;
    
    public VRKeyStoreDAOX509KeyManager(VRKeyStoreDAO keyStoreDAO)
    {
        this.keyStoreDAO = keyStoreDAO;
        sniMatcher = null;
    }
    
    void setVRSNIMatcher(VRSNIMatcher sniMatcher)
    {
        this.sniMatcher = sniMatcher;
    }
    
    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine)
    {
        return null;
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        LOG.debug(keyType);
//        return super.chooseEngineServerAlias(keyType, issuers, engine);
//        String alias = keyManager.chooseEngineServerAlias(keyType, issuers, engine);
//        return alias;
        return keyManager.chooseEngineServerAlias(keyType, issuers, engine);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return keyManager.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias)
    {
        return keyManager.getCertificateChain(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias)
    {
        return keyManager.getPrivateKey(alias);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return keyManager.getServerAliases(keyType, issuers);
    }
}
