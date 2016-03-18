/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author ahonore
 *
 */
public class KeyStoreMetaDataTest
{
    private KeyStoreMetaData keyStoreMetaData;
    private final String masterPassword = "test-integrity";
    
    @Before
    public void setUp() throws Exception
    {
        keyStoreMetaData = KeyStoreMetaData.generate(masterPassword.toCharArray());
    }

    @Test(expected=UnrecoverableKeyException.class)
    public void testIntegrityWrongMasterPassword() throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        keyStoreMetaData.checkIntegrity("bad password".toCharArray());
    }

    @Test
    public void testIntegrityRightMasterPassword() throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        keyStoreMetaData.checkIntegrity(masterPassword.toCharArray());
    }

    @Test
    public void testCipherDecipherData() throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        final String keyPassword = "key-password";
        keyStoreMetaData.checkIntegrity(masterPassword.toCharArray());
        
        byte[] data = "the data to be ciphered".getBytes(StandardCharsets.UTF_8);
        byte[] cipheredData = keyStoreMetaData.cipherKey(keyPassword.toCharArray(), data);
        byte[] decipheredData = keyStoreMetaData.decipherKey(keyPassword.toCharArray(), cipheredData);
        Assert.assertArrayEquals(data, decipheredData);
    }
}
