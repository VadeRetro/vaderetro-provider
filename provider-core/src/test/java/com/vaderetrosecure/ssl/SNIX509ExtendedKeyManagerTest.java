/**
 * 
 */
package com.vaderetrosecure.ssl;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;

/**
 *
 */
public class SNIX509ExtendedKeyManagerTest
{
    private final static Logger LOG = Logger.getLogger(SNIX509ExtendedKeyManagerTest.class);

    private static final String MASTER_PASSWORD = "master-password";
    private static final String KEY_PASSWORD = "key-password";

    private static final String PRIVATE_KEY_AND_CERTIFICATE_ALIAS = "private-certificate-alias";
    
    private static KeyStoreEntry privateKeyEntry;
    private static PrivateKey privateKey;
    private static Certificate certificate;
    private static PrivateKey keyManagerPrivateKey;
    private static PublicKey vrKeyStorePublicKey;
    private static IntegrityData integrityData;
    
    private KeyStoreDAO ksdao;
    private SNIX509ExtendedKeyManager keyManager;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        integrityData = new IntegrityData(MASTER_PASSWORD.toCharArray());
        KeyProtection kp = KeyProtection.generateKeyProtection(KEY_PASSWORD.toCharArray(), integrityData.getSalt());
        Date creationDate = Date.from(Instant.now());
        
        KeyFactory kf = KeyFactory.getInstance("RSA");

        try
        {
            URL url = Thread.currentThread().getContextClassLoader().getResource("public.key");
            byte[] encKey = Files.readAllBytes(Paths.get(url.toURI()));
            vrKeyStorePublicKey = kf.generatePublic(new X509EncodedKeySpec(encKey));
        }
        catch (Exception e)
        {
            LOG.fatal(e, e);
            throw e;
        }
        
        try
        {
            URL url = Thread.currentThread().getContextClassLoader().getResource("private.key");
            byte[] encKey = Files.readAllBytes(Paths.get(url.toURI()));
            keyManagerPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encKey));
        }
        catch (Exception e)
        {
            LOG.fatal(e, e);
            throw e;
        }

        try
        {
            URL url = Thread.currentThread().getContextClassLoader().getResource("test.com.key");
            byte[] encData = Files.readAllBytes(Paths.get(url.toURI()));
            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encData));

            try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("test.com.crt"))
            {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                certificate = cf.generateCertificate(is);
            }

            privateKeyEntry = new KeyStoreEntry(PRIVATE_KEY_AND_CERTIFICATE_ALIAS, creationDate, privateKey, kp, Collections.singletonList(new CertificateData(certificate)), Collections.singletonList("test.com"));
            privateKeyEntry.setLockedKeyProtection(kp.getLockedKeyProtection(vrKeyStorePublicKey));
//            privateKeyEntry.setLockedKeyProtection(kp.getLockedKeyProtection(null));
        }
        catch (Exception e)
        {
            LOG.fatal(e, e);
            throw e;
        }
    }

    @Before
    public void setUp() throws Exception
    {
        ksdao = mock(KeyStoreDAO.class);
        when(ksdao.getIntegrityData()).thenReturn(integrityData);
        when(ksdao.getEntry(eq(PRIVATE_KEY_AND_CERTIFICATE_ALIAS))).thenReturn(privateKeyEntry);
        when(ksdao.getAliases(eq("RSA"))).thenReturn(Collections.singletonList(PRIVATE_KEY_AND_CERTIFICATE_ALIAS));
        
        keyManager = new SNIX509ExtendedKeyManager(ksdao, keyManagerPrivateKey);
//        keyManager = new SNIX509ExtendedKeyManager(ksdao, null);
    }

    @Test(expected=UnsupportedOperationException.class)
    public void testChooseEngineClientAlias()
    {
        keyManager.chooseEngineClientAlias(null, null, null);
    }

//    @Test
//    public void testChooseEngineServerAlias()
//    {
//        keyManager.chooseEngineServerAlias(null, null, null);
//    }

    @Test(expected=UnsupportedOperationException.class)
    public void testChooseClientAlias()
    {
        keyManager.chooseClientAlias(null, null, null);
    }

//    @Override
//    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
//    {
//        String[] aliases = getServerAliases(keyType, issuers);
//        if (aliases == null)
//            return null;
//        
//        return getSelectedSNIAlias(keyType, issuers, ((SSLSocket) socket).getSSLParameters().getSNIMatchers());
//    }

    @Test
    public void testGetCertificateChain() throws CertificateEncodingException
    {
        X509Certificate[] certs = keyManager.getCertificateChain(PRIVATE_KEY_AND_CERTIFICATE_ALIAS);
        Assert.assertEquals(1, certs.length);
        Assert.assertArrayEquals(certificate.getEncoded(), certs[0].getEncoded());
    }

    @Test(expected=UnsupportedOperationException.class)
    public void testGetClientAliases()
    {
        keyManager.getClientAliases(null, null);
    }

    @Test
    public void testGetPrivateKey()
    {
        PrivateKey pk = keyManager.getPrivateKey(PRIVATE_KEY_AND_CERTIFICATE_ALIAS);
        Assert.assertNotNull(pk);
        Assert.assertArrayEquals(privateKey.getEncoded(), pk.getEncoded());
    }

    @Test
    public void testGetServerAliases()
    {
        String[] aliases = keyManager.getServerAliases("RSA", null);
        Assert.assertEquals(1, aliases.length);
        Assert.assertEquals(PRIVATE_KEY_AND_CERTIFICATE_ALIAS, aliases[0]);
    }
}
