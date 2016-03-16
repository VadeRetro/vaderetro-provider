/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509ExtendedKeyManager;

/**
 * @author ahonore
 *
 */
public class VRSNIX509ExtendedKeyManager extends X509ExtendedKeyManager
{

    @Override
    public String chooseClientAlias(String[] arg0, Principal[] arg1, Socket arg2)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String chooseServerAlias(String arg0, Principal[] arg1, Socket arg2)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String arg0)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String[] getClientAliases(String arg0, Principal[] arg1)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String arg0)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String[] getServerAliases(String arg0, Principal[] arg1)
    {
        // TODO Auto-generated method stub
        return null;
    }

}
