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
 * This is the class to access all Vade Retro services.
 * To add an instance at runtime, use:<br>
 * <br>
 * <code>
 *  import java.security.Provider;<br>
 *  import com.vaderetrosecure.VadeRetroProvider;<br>
 *  <br>
 *  Security.addProvider(new VadeRetroProvider());<br>
 * </code>
 * <br>
 * The provider can also be configured as part of your environment via static registration by adding an entry to 
 * the java.security properties file (found in {@code $JAVA_HOME/jre/lib/security/java.security}, where {@code $JAVA_HOME} is the location of 
 * your JDK/JRE distribution). You'll find detailed instructions in the file but basically it comes down to adding a line:<br>
 * <br>
 * {@code security.provider.<n>=com.vaderetrosecure.VadeRetroProvider}<br>
 * <br>
 * where {@code <n>} is the preference you want the provider at (1 being the most preferred).
 *  
 * @author ahonore
 */
public class VadeRetroProvider extends Provider
{
    private static final long serialVersionUID = -5763788919498367657L;
    
    /**
     * The name of the Vade Retro provider. This variable can be used to avoid manipulating a string in the code.
     */
    public static final String VR_PROVIDER = "VR";

    /**
     * Construct a new provider.
     */
    public VadeRetroProvider()
    {
        super(VR_PROVIDER, 0.1, "Vade Retro Security provider");

        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            @Override
            public Object run()
            {
                put("KeyStore.KS", VRKeyStoreSpi.class.getName());
                put("KeyManagerFactory.X509", VRKeyManagerFactorySpi.class.getName());
                put("SSLContext.TLS", TLSSSLContextSpi.class.getName());
                return null;
            }
        });
    }
}
