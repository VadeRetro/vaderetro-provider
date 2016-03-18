/**
 * 
 */
package com.vaderetrosecure.keystore;

import static org.mockito.Matchers.anyCollectionOf;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Collections;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.vaderetrosecure.VadeRetroProvider;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class VRKeystoreSpiTest
{
    private static final String MASTER_PASSWORD = "master-password";

    private SecretKey secretKey;
    private VRKeystoreSpi keystore;
    private VRKeyStoreDAO ksdao;
    
    @Before
    public void setUp() throws Exception
    {
        secretKey = new SecretKeySpec("secret key".getBytes(StandardCharsets.US_ASCII), "AES");
        
        KeyStoreMetaData ksemd = KeyStoreMetaData.generate(MASTER_PASSWORD.toCharArray());
        ksdao = mock(VRKeyStoreDAO.class);
        when(ksdao.getMetaData()).thenReturn(ksemd);
        
        keystore = new VRKeystoreSpi(ksdao);
    }

    @Test
    public void testGetInstanceFromVRProvider() throws KeyStoreException, NoSuchProviderException
    {
        System.setProperty(VRKeyStoreDAOFactory.DAO_FACTORY_CLASS_NAME, MockVRKeyStoreDAOFactory.class.getName());
        Security.addProvider(new VadeRetroProvider());
        KeyStore ks = KeyStore.getInstance("VR");
        Assert.assertEquals("VR", ks.getProvider().getName());
    }

    @Test(expected=IOException.class)
    public void testLoadWrongPassword() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException
    {
        keystore.engineLoad(null, "sfkghshiistgohstio".toCharArray());
    }

    @Test
    public void testLoadRightPassword() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException
    {
        keystore.engineLoad(null, MASTER_PASSWORD.toCharArray());
    }

    @Test(expected=UnrecoverableKeyException.class)
    public void testStoreLoadSecretKeyWrongPassword() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableKeyException, VRKeyStoreDAOException
    {
        doAnswer(new Answer<Object>() {
            @SuppressWarnings("unchecked")
            public Object answer(InvocationOnMock invocation) throws VRKeyStoreDAOException {
                Object[] args = invocation.getArguments();
                KeyStoreEntry kse = ((Collection<KeyStoreEntry>) args[0]).toArray(new KeyStoreEntry[]{})[0];
                VRKeyStoreDAO mock = (VRKeyStoreDAO) invocation.getMock();
                when(mock.getKeyStoreEntry(eq("key-alias"), eq(KeyStoreEntryType.SECRET_KEY))).thenReturn(Collections.singletonList(kse));
                return null;
            }})
        .when(ksdao).setKeyStoreEntries(anyCollectionOf(KeyStoreEntry.class));
        
        keystore.engineLoad(null, MASTER_PASSWORD.toCharArray());
        keystore.engineSetKeyEntry("key-alias", secretKey, "key-password".toCharArray(), null);
        keystore.engineGetKey("key-alias", "sxfthdfhdhy".toCharArray());
    }

    @Test
    public void testStoreLoadSecretKeyRightPassword() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableKeyException, VRKeyStoreDAOException
    {
        doAnswer(new Answer<Object>() {
            @SuppressWarnings("unchecked")
            public Object answer(InvocationOnMock invocation) throws VRKeyStoreDAOException {
                Object[] args = invocation.getArguments();
                KeyStoreEntry kse = ((Collection<KeyStoreEntry>) args[0]).toArray(new KeyStoreEntry[]{})[0];
                VRKeyStoreDAO mock = (VRKeyStoreDAO) invocation.getMock();
                when(mock.getKeyStoreEntry(eq("key-alias"), eq(KeyStoreEntryType.SECRET_KEY))).thenReturn(Collections.singletonList(kse));
                return null;
            }})
        .when(ksdao).setKeyStoreEntries(anyCollectionOf(KeyStoreEntry.class));
        keystore.engineLoad(null, MASTER_PASSWORD.toCharArray());
        keystore.engineSetKeyEntry("key-alias", secretKey, "key-password".toCharArray(), null);
        Key k = keystore.engineGetKey("key-alias", "key-password".toCharArray());
        
        Assert.assertArrayEquals(secretKey.getEncoded(), k.getEncoded());
    }

    @Test
    public void testStoreLoadCertificate() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableKeyException, VRKeyStoreDAOException
    {
        doAnswer(new Answer<Object>() {
            @SuppressWarnings("unchecked")
            public Object answer(InvocationOnMock invocation) throws VRKeyStoreDAOException {
                Object[] args = invocation.getArguments();
                KeyStoreEntry kse = ((Collection<KeyStoreEntry>) args[0]).toArray(new KeyStoreEntry[]{})[0];
                VRKeyStoreDAO mock = (VRKeyStoreDAO) invocation.getMock();
                when(mock.getKeyStoreEntry(eq("key-alias"), eq(KeyStoreEntryType.SECRET_KEY))).thenReturn(Collections.singletonList(kse));
                return null;
            }})
        .when(ksdao).setKeyStoreEntries(anyCollectionOf(KeyStoreEntry.class));
        keystore.engineLoad(null, MASTER_PASSWORD.toCharArray());
        keystore.engineSetKeyEntry("key-alias", secretKey, "key-password".toCharArray(), null);
        Key k = keystore.engineGetKey("key-alias", "key-password".toCharArray());
        
        Assert.assertArrayEquals(secretKey.getEncoded(), k.getEncoded());
    }
    
    public static class MockVRKeyStoreDAOFactory extends VRKeyStoreDAOFactory
    {
        @Override
        protected void init(Properties properties) throws VRKeyStoreDAOException
        {
        }

        @Override
        public VRKeyStoreDAO getKeyStoreDAO() throws VRKeyStoreDAOException
        {
            return null;
        }
    }
}
