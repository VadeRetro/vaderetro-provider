/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

/**
 * @author ahonore
 *
 */
public class VRKeyManagerSpi extends KeyManagerFactorySpi
{

    @Override
    protected KeyManager[] engineGetKeyManagers()
    {
        return null;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException
    {
    }

    @Override
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        // TODO Auto-generated method stub

    }
}
