/**
 * 
 */
package com.vaderetrosecure;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.net.ssl.SSLContext;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;
import com.vaderetrosecure.keystore.dao.IntegrityData;

/**
 * @author ahonore
 *
 */
public class VadeRetroProviderTest
{
    private VadeRetroProvider vrProvider = new VadeRetroProvider();
    
    @Before
    public void setUp() throws Exception
    {
        Security.addProvider(vrProvider);
    }

    @Ignore
    @Test
    public void testGetKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        System.setProperty(KeyStoreDAOFactory.DAO_FACTORY_CLASS_NAME, MockVRKeyStoreDAOFactory.class.getName());
        KeyStore ks = KeyStore.getInstance(vrProvider.getName());
        ks.load(null, null);
    }

    @Test
    public void testGetSSLContext() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException
    {
        SSLContext.getInstance("TLS", vrProvider.getName());
    }

    public static class MockVRKeyStoreDAOFactory extends KeyStoreDAOFactory
    {
        @Override
        protected void init(Properties properties) throws KeyStoreDAOException
        {
        }

        @Override
        public KeyStoreDAO getKeyStoreDAO() throws KeyStoreDAOException
        {
            KeyStoreDAO ksdao = mock(KeyStoreDAO.class);
            try
            {
                when(ksdao.getIntegrityData()).thenReturn(new IntegrityData(null));
            }
            catch (Exception e)
            {
                throw new KeyStoreDAOException(e);
            }
            return ksdao;
        }
    }
}
