/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.log4j.Logger;

/**
 * The SSLContext of the Vade Retro Provider.
 * This SSL context is backed by a DAO, so a DAO implementation must be provided for this class to work.
 * To use it:
 * <pre>
 * <code>
 * KeyStore ks = KeyStore.getInstance("KS", VadeRetroProvider.VR_PROVIDER);
 * KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509", VadeRetroProvider.VR_PROVIDER);
 * kmf.init(ks, null);
 * SSLContext sslCtx = SSLContext.getInstance("TLS", VadeRetroProvider.VR_PROVIDER);
 * sslCtx.init(kmf.getKeyManagers(), null, null);</code></pre>
 * This context delegates most of its behavior to the default TLS context. But it adds the SNI management 
 * and the DAO access to retrieve certificates and private keys.
 * 
 * @author ahonore
 */
public class TLSSSLContextSpi extends SSLContextSpi
{
    private static final Logger LOG = Logger.getLogger(TLSSSLContextSpi.class);

    private SSLContext delegate;
    private List<SNIX509ExtendedKeyManager> sniX509ExtendedKeyManagers;

    public TLSSSLContextSpi()
    {
        sniX509ExtendedKeyManagers = new ArrayList<>();

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
        List<SNIMatcher> sniMatchers = createSNIMatchers(sniX509ExtendedKeyManagers);
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
        List<SNIMatcher> sniMatchers = createSNIMatchers(sniX509ExtendedKeyManagers);
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
                sniX509ExtendedKeyManagers.add((SNIX509ExtendedKeyManager) k);

        delegate.init(km, tm, random);
    }
    
    private List<SNIMatcher> createSNIMatchers(List<SNIX509ExtendedKeyManager> sniX509ExtendedKeyManagers)
    {
        return sniX509ExtendedKeyManagers.stream().map(k -> new VRSNIMatcher(k.getKeyStoreDAO())).collect(Collectors.toList());
    }
}
