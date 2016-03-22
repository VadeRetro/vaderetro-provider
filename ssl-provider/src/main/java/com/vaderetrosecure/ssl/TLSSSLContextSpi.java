/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.TrustManager;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreDAO;

/**
 * @author ahonore
 *
 */
public class TLSSSLContextSpi extends SSLContextSpi
{
    private static final Logger LOG = Logger.getLogger(TLSSSLContextSpi.class);

    private SSLContext delegate;
    private List<SNIMatcher> sniMatchers;

    public TLSSSLContextSpi()
    {
        sniMatchers = new ArrayList<>();

        try
        {
            this.delegate = SSLContext.getInstance("TLS");
        }
        catch (NoSuchAlgorithmException e)
        {
        	LOG.fatal(e, e);
        	throw new IllegalStateException(e);
        }
    }
    
    @Override
    protected SSLEngine engineCreateSSLEngine()
    {
        SSLEngine sslEngine = delegate.createSSLEngine();
        SSLParameters sslParams = sslEngine.getSSLParameters();
        if (!sniMatchers.isEmpty())
            sslParams.setSNIMatchers(sniMatchers);
        sslEngine.setSSLParameters(sslParams);
        return sslEngine;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String peerHost, int peerPort)
    {
        SSLEngine sslEngine = delegate.createSSLEngine(peerHost, peerPort);
        SSLParameters sslParams = sslEngine.getSSLParameters();
        if (!sniMatchers.isEmpty())
            sslParams.setSNIMatchers(sniMatchers);
        LOG.debug("CIPHER SUITES: " + String.join(",", sslParams.getCipherSuites()));
        sslEngine.setSSLParameters(sslParams);
        return sslEngine;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext()
    {
        return delegate.getClientSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext()
    {
        return delegate.getServerSessionContext();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory()
    {
        return delegate.getServerSocketFactory();
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory()
    {
        return delegate.getSocketFactory();
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom random) throws KeyManagementException
    {
        for (KeyManager k : km)
            if (SNIX509ExtendedKeyManager.class.isInstance(k))
                sniMatchers.add(new VRSNIMatcher(((SNIX509ExtendedKeyManager) k).getKeyStoreDAO()));

        delegate.init(km, tm, random);
    }
}
