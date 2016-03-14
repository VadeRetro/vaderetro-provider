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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.vaderetrosecure.VRKeyStorageDAO;

/**
 * @author ahonore
 *
 */
public class VRX509KeyManager extends X509ExtendedKeyManager
{
    private final static Logger LOGGER = LoggerFactory.getLogger(VRX509KeyManager.class);

    private final VRKeyStorageDAO keyStorage;
    private VRSNIMatcher sniMatcher;
    
    public VRX509KeyManager(VRKeyStorageDAO keyStorage)
    {
        this.keyStorage = keyStorage;
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
        LOGGER.debug(keyType);
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
