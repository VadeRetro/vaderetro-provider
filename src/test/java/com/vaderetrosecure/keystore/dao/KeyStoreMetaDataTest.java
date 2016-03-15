/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Before;
import org.junit.Test;

/**
 * @author ahonore
 *
 */
public class KeyStoreMetaDataTest
{
    @Before
    public void setUp() throws Exception
    {
    }

    @Test
    public void testIntegrityAfterGeneration() throws UnrecoverableKeyException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        SecureRandom sr = new SecureRandom();
        String password = "test-integrity";
        byte[] salt = new byte[8];
        sr.nextBytes(salt);
        KeyStoreMetaData id = KeyStoreMetaData.generate(1, "1.0.0", password.toCharArray());
        id.checkIntegrity(password.toCharArray());
    }
}
