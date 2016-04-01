/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

/**
 * @author ahonore
 *
 */
public class IntegrityData
{
    private static final Logger LOG = Logger.getLogger(IntegrityData.class);
    
    private byte[] salt;
    private byte[] iv;
    private byte[] cipheredData;
    private byte[] dataHash;
    
    public IntegrityData()
    {
        this(CipheringTools.generateRandomBytes(16), CipheringTools.generateIV(), new byte[]{}, new byte[]{});
    }

    public IntegrityData(byte[] salt, byte[] iv, byte[] cipheredData, byte[] dataHash)
    {
        setSalt(salt);
        setIV(iv);
        setCipheredData(cipheredData);
        setDataHash(dataHash);
    }

    /**
     * Generate a new integrity ciphering.
     * Can be used change the password without loosing salt data.
     * 
     * @param salt
     * @param password
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public IntegrityData(byte[] salt, char[] password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setSalt(salt);
        generateIntegrity(password);
    }

    /**
     * Generate a completely new integrity data object.
     * 
     * @param password
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public IntegrityData(char[] password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        this();
        generateIntegrity(password);
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public void setSalt(byte[] salt)
    {
        this.salt = salt;
    }

    public byte[] getIV()
    {
        return iv;
    }

    public void setIV(byte[] iv)
    {
        this.iv = iv;
    }

    public byte[] getCipheredData()
    {
        return cipheredData;
    }

    public void setCipheredData(byte[] cipheredData)
    {
        this.cipheredData = cipheredData;
    }

    public byte[] getDataHash()
    {
        return dataHash;
    }

    public void setDataHash(byte[] dataHash)
    {
        this.dataHash = dataHash;
    }
    
    private void generateIntegrity(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setIV(CipheringTools.generateIV());
        byte[] integrityData = CipheringTools.generateRandomBytes(64);
        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        setDataHash(sha2.digest(integrityData));
        SecretKey secret = CipheringTools.getAESSecretKey(password, getSalt());
        setCipheredData(CipheringTools.cipherData(integrityData, secret, getIV()));
    }
    
    public void checkIntegrity(char[] password) throws UnrecoverableKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        try
        {
            SecretKey secret = CipheringTools.getAESSecretKey(password, getSalt());
            MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
            byte[] data = CipheringTools.decipherData(getCipheredData(), secret, getIV());
            if (!Arrays.equals(getDataHash(), sha2.digest(data)))
                throw new UnrecoverableKeyException("integrity check failed");
        }
        catch (InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
            throw new UnrecoverableKeyException("integrity check failed");
        }
    }
}
