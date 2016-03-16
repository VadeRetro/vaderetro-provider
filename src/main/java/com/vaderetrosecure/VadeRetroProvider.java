/**
 * 
 */
package com.vaderetrosecure;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import com.vaderetrosecure.keystore.VRKeystoreSpi;
import com.vaderetrosecure.ssl.VRKeyManagerFactorySpi;
import com.vaderetrosecure.ssl.VRSSLContextSpi;

/**
 * @author ahonore
 *
 */
public class VadeRetroProvider extends Provider
{
    private static final long serialVersionUID = -5763788919498367657L;
    private static final String VR_PROVIDER = "VR";

    public VadeRetroProvider()
    {
        super(VR_PROVIDER, 0.1, "Vade Retro Security provider");

        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            @Override
            public Object run()
            {
                put("KeyStore.VR", VRKeystoreSpi.class.getName());
                put("SSLContext.TLS", VRSSLContextSpi.class.getName());
                put("KeyManagerFactory.VR", VRKeyManagerFactorySpi.class.getName());
                return null;
            }
        });
    }
}
