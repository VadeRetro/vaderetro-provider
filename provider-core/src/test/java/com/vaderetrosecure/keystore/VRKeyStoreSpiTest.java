/**
 * 
 */
package com.vaderetrosecure.keystore;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.InvalidNameException;

import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;

/**
 *
 */
public class VRKeyStoreSpiTest
{
    private final static Logger LOG = Logger.getLogger(VRKeyStoreSpiTest.class);

    private static final String MASTER_PASSWORD = "master-password";
    private static final String SECRET_KEY_ALIAS = "secret-alias";
    private static final String PRIVATE_KEY_AND_CERTIFICATE_ALIAS = "private-certificate-alias";
    private static final String TRUSTED_CERTIFICATE_ALIAS = "trusted-certificate-alias";

    private static SecretKey secretKey;
    private static PrivateKey privKey;
    private static Certificate cert;
    private VRKeyStoreSpi keystore;
    private KeyStoreDAO ksdao;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        secretKey = new SecretKeySpec("secret key".getBytes(StandardCharsets.US_ASCII), "AES");

        try
        {
            URL url = Thread.currentThread().getContextClassLoader().getResource("test.com.key");
            byte[] encData = Files.readAllBytes(Paths.get(url.toURI()));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encData));
        }
        catch (Exception e)
        {
            LOG.fatal(e, e);
            throw e;
        }
        
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("test.com.crt"))
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(is);
        }
    }
    
    @Before
    public void setUp() throws Exception
    {
        IntegrityData id = new IntegrityData(MASTER_PASSWORD.toCharArray());
        ksdao = mock(KeyStoreDAO.class);
        when(ksdao.getIntegrityData()).thenReturn(id);
        
        keystore = new VRKeyStoreSpi(ksdao);
    }

    @Test(expected=IOException.class)
    public void testLoadWrongPassword() throws NoSuchAlgorithmException, CertificateException, IOException
    {
        keystore.engineLoad(null, MASTER_PASSWORD.toCharArray());
        keystore.engineLoad(null, "sfkghshiistgohstio".toCharArray());
    }

    @Test
    public void testLoadRightPassword() throws NoSuchAlgorithmException, CertificateException, IOException
    {
        keystore.engineLoad(null, MASTER_PASSWORD.toCharArray());
    }

    @Test
    public void testEngineSetKeyEntryWithSecretKey() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, KeyStoreDAOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException
    {
        ArgumentCaptor<KeyStoreEntry> argument = ArgumentCaptor.forClass(KeyStoreEntry.class);
        
        keystore.engineLoad(null, null);
        keystore.engineSetKeyEntry(SECRET_KEY_ALIAS, secretKey, null, null);

        verify(ksdao).setEntry(argument.capture());
        Assert.assertEquals(SECRET_KEY_ALIAS, argument.getValue().getAlias());
        KeyProtection kp = new KeyProtection(argument.getValue().getLockedKeyProtection(), null);
        Assert.assertArrayEquals(secretKey.getEncoded(), argument.getValue().getKey(kp).getEncoded());
    }

    @Test
    public void testEngineSetEntryWithPrivateKeyAndCertificateChain() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, KeyStoreDAOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException
    {
        ArgumentCaptor<KeyStoreEntry> argPKEntry = ArgumentCaptor.forClass(KeyStoreEntry.class);
        
        keystore.engineLoad(null, null);
        keystore.engineSetKeyEntry(PRIVATE_KEY_AND_CERTIFICATE_ALIAS, privKey, null, new Certificate[]{ cert });

        verify(ksdao).setEntry(argPKEntry.capture());
        KeyStoreEntry kse = argPKEntry.getValue();
        Assert.assertNotNull(kse);
        Assert.assertEquals(PRIVATE_KEY_AND_CERTIFICATE_ALIAS, kse.getAlias());
        Assert.assertEquals(KeyStoreEntryType.PRIVATE_KEY, kse.getEntryType());
        KeyProtection kp = new KeyProtection(argPKEntry.getValue().getLockedKeyProtection(), null);
        Assert.assertArrayEquals(privKey.getEncoded(), kse.getKey(kp).getEncoded());
        Assert.assertEquals(1, kse.getCertificateChain().size());
        Assert.assertArrayEquals(cert.getEncoded(), kse.getCertificateChain().get(0).getCertificate().getEncoded());
    }

    @Test(expected=UnrecoverableKeyException.class)
    public void testEngineGetKeyEntryWithPrivateKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, KeyStoreDAOException, CertificateException, IOException, UnrecoverableKeyException
    {
        KeyProtection kp = KeyProtection.generateKeyProtection("password".toCharArray(), ksdao.getIntegrityData().getSalt());
        KeyStoreEntry ksePK = new KeyStoreEntry(PRIVATE_KEY_AND_CERTIFICATE_ALIAS, Date.from(Instant.now()), privKey, kp, Collections.emptyList(), Collections.emptyList());
        when(ksdao.getEntry(anyString())).thenReturn(ksePK);
        
        keystore.engineLoad(null, null);
        Key k = keystore.engineGetKey(PRIVATE_KEY_AND_CERTIFICATE_ALIAS, "password".toCharArray());
        Assert.assertTrue(PrivateKey.class.isInstance(k));
        Assert.assertArrayEquals(privKey.getEncoded(), k.getEncoded());
        
        keystore.engineGetKey(PRIVATE_KEY_AND_CERTIFICATE_ALIAS, "wfgbkljnsmkgklmjb".toCharArray());
    }

    @Test
    public void testEngineGetCertificateEntry() throws InvalidNameException, KeyStoreDAOException, NoSuchAlgorithmException, CertificateException, IOException
    {
        KeyStoreEntry kse = new KeyStoreEntry(TRUSTED_CERTIFICATE_ALIAS, Date.from(Instant.now()), cert);
        when(ksdao.getEntry(anyString())).thenReturn(kse);
        
        keystore.engineLoad(null, null);
        Certificate c = keystore.engineGetCertificate(TRUSTED_CERTIFICATE_ALIAS);

        Assert.assertArrayEquals(cert.getEncoded(), c.getEncoded());
    }
    
    public static class MockVRKeyStoreDAOFactory extends KeyStoreDAOFactory
    {
        @Override
        protected void init() throws KeyStoreDAOException
        {
        }

        @Override
        public KeyStoreDAO getKeyStoreDAO() throws KeyStoreDAOException
        {
            return null;
        }
    }
}
