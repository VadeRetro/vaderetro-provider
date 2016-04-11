/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
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
public class IntegrityDataTest
{
    private IntegrityData integrityData;
    private final String masterPassword = "test-integrity";
    
    @Before
    public void setUp() throws Exception
    {
        integrityData = new IntegrityData(masterPassword.toCharArray());
    }

    @Test(expected=UnrecoverableKeyException.class)
    public void testIntegrityWrongMasterPassword() throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        integrityData.checkIntegrity("bad password".toCharArray());
    }

    @Test
    public void testIntegrityRightMasterPassword() throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        integrityData.checkIntegrity(masterPassword.toCharArray());
    }

    @Test(expected=UnrecoverableKeyException.class)
    public void testIntegrityBroken() throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        integrityData.setCipheredData(CryptoTools.generateRandomBytes(64));
        integrityData.checkIntegrity(masterPassword.toCharArray());
    }
    
    @Test
    public void testIntegrityNewMasterPassword() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, IOException
    {
        final String newMasterPassword = "test-integrity-new";
        IntegrityData id = new IntegrityData(integrityData.getSalt(), newMasterPassword.toCharArray());
        integrityData.checkIntegrity(masterPassword.toCharArray());
        id.checkIntegrity(newMasterPassword.toCharArray());
        
        Assert.assertArrayEquals(integrityData.getSalt(), id.getSalt());
    }
}
