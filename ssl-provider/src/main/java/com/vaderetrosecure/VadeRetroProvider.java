/**
 * 
 */
package com.vaderetrosecure;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import com.vaderetrosecure.keystore.VRKeyStoreSpi;
import com.vaderetrosecure.ssl.VRKeyManagerFactorySpi;
import com.vaderetrosecure.ssl.TLSSSLContextSpi;

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
                put("KeyStore.VR", VRKeyStoreSpi.class.getName());
                put("KeyStore.KS", VRKeyStoreSpi.class.getName());
                put("KeyManagerFactory.VR", VRKeyManagerFactorySpi.class.getName());
                put("KeyManagerFactory.X509", VRKeyManagerFactorySpi.class.getName());
                put("SSLContext.TLS", TLSSSLContextSpi.class.getName());
                return null;
            }
        });
    }
}
