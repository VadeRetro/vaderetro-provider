/**
 * 
 */
package com.vaderetrosecure;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

import org.apache.log4j.Logger;

import com.vaderetrosecure.ssl.VRSSLContextSpi;

/**
 * @author ahonore
 *
 */
public class VadeRetroProvider extends Provider
{
    private static final long serialVersionUID = -5763788919498367657L;

//    private static final Logger LOG = Logger.getLogger(FileKeystoreProvider.class);
    private static final String VR_PROVIDER = "VR";

    public VadeRetroProvider()
    {
        super(VR_PROVIDER, 0.1, "Vade Retro Security provider");
        

        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {

            @Override
            public Object run()
            {
                put("KeyStore.VR", FileKeystore.class.getName());
                put("SSLContext.TLS", VRSSLContextSpi.class.getName());
                return null;
            }
        });

    }
}
