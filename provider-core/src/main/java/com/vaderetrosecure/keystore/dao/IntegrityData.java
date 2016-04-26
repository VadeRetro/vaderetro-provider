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
 * This object represents integrity data that can be eventually checked.
 * The check is done using a password:<br>
 * <ul>
 * <li>an AES-256 key is created, using the {@code salt}</li>
 * <li>the {@code cipheredData} is deciphered, using the key and the {@code iv}</li>
 * <li>the data is compared to {@code dataHash}</li>
 * </ul>
 * <br>
 * The salt is used by all key protection objects to generate keys. Constructors are given to 
 * easily generate new integrity data.<br>
 * Each field is an array of bytes to be easily stored.
 */
public class IntegrityData
{
    private static final Logger LOG = Logger.getLogger(IntegrityData.class);
    
    private byte[] salt;
    private byte[] iv;
    private byte[] cipheredData;
    private byte[] dataHash;
    
    /**
     * Construct a new IntegrityData object with generated fields.
     */
    public IntegrityData()
    {
        this(CryptoTools.generateRandomBytes(16), CryptoTools.generateIV(), new byte[]{}, new byte[]{});
    }

    /**
     * Construct a new IntegrityData object given fields.
     * 
     * @param salt the salt used to generated keys using passwords.
     * @param iv the initialization vector of the AES cipherer.
     * @param cipheredData data to be evaluated on an integrity check.
     * @param dataHash SHA-256 hash of the data to be compared with data.
     */
    public IntegrityData(byte[] salt, byte[] iv, byte[] cipheredData, byte[] dataHash)
    {
        setSalt(salt);
        setIV(iv);
        setCipheredData(cipheredData);
        setDataHash(dataHash);
    }

    /**
     * Generate a new IntegrityData object, given new salt and password fields.
     * Can be used to change the password without loosing salt data.
     * 
     * @param salt the salt used to generated keys using passwords.
     * @param password the password used to generate new integrity data value.
     * @throws InvalidKeyException if the generated key is wrong.
     * @throws NoSuchAlgorithmException if used algorithms can not be found.
     * @throws InvalidKeySpecException if keys can not be created.
     * @throws NoSuchPaddingException if ciphering can not be performed.
     * @throws InvalidAlgorithmParameterException if the ciphering algorithm can not used with this {@code iv}.
     * @throws IllegalBlockSizeException if the ciphering can not be performed.
     * @throws BadPaddingException if the ciphering can not be performed.
     */
    public IntegrityData(byte[] salt, char[] password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setSalt(salt);
        generateIntegrity(password);
    }

    /**
     * Generate a new IntegrityData object, given a new password.
     * The salt will be generated.
     * 
     * @param password the password used to generate new integrity data value.
     * @throws InvalidKeyException if the generated key is wrong.
     * @throws NoSuchAlgorithmException if used algorithms can not be found.
     * @throws InvalidKeySpecException if keys can not be created.
     * @throws NoSuchPaddingException if ciphering can not be performed.
     * @throws InvalidAlgorithmParameterException if the ciphering algorithm can not used with this {@code iv}.
     * @throws IllegalBlockSizeException if the ciphering can not be performed.
     * @throws BadPaddingException if the ciphering can not be performed.
     */
    public IntegrityData(char[] password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        this();
        generateIntegrity(password);
    }

    /**
     * Return the salt for generated password keys.
     * 
     * @return the salt as an array of bytes.
     */
    public byte[] getSalt()
    {
        return salt;
    }

    /**
     * Define the salt for generated password keys.
     * @param salt the salt as an array of bytes.
     */
    public void setSalt(byte[] salt)
    {
        this.salt = salt;
    }

    /**
     * Retrieve the initialization vector to cipher/decipher data.
     * 
     * @return the initialization vector as an array of bytes.
     */
    public byte[] getIV()
    {
        return iv;
    }

    /**
     * Set the initialization vector for ciphering/deciphering data.
     * 
     * @param iv the initialization vector.
     */
    public void setIV(byte[] iv)
    {
        this.iv = iv;
    }

    /**
     * Return the ciphered data, processed when a check is performed.
     * 
     * @return the ciphered data.
     */
    public byte[] getCipheredData()
    {
        return cipheredData;
    }

    /**
     * Define the ciphered data.
     * This field is generated, so using this method with arrays not generated 
     * by an other integrity data is strongly discouraged.
     * 
     * @param cipheredData the ciphered data.
     */
    public void setCipheredData(byte[] cipheredData)
    {
        this.cipheredData = cipheredData;
    }

    /**
     * Return the hash of the data from the {@code cipheredData} field.
     * 
     * @return the hash of the data.
     */
    public byte[] getDataHash()
    {
        return dataHash;
    }

    /**
     * Define the hash of the data from the {@code cipheredData} field.
     * This field is generated, so using this method with arrays not generated 
     * by an other integrity data is strongly discouraged.
     * 
     * @param dataHash the hash of the data.
     */
    public void setDataHash(byte[] dataHash)
    {
        this.dataHash = dataHash;
    }
    
    private void generateIntegrity(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setIV(CryptoTools.generateIV());
        byte[] integrityData = CryptoTools.generateRandomBytes(64);
        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        setDataHash(sha2.digest(integrityData));
        SecretKey secret = CryptoTools.getAESSecretKey(password, getSalt());
        setCipheredData(CryptoTools.cipherData(integrityData, secret, getIV()));
    }
    
    /**
     * Check the integrity, given a password.
     * If the check succeeded, the method returns normally. Otherwise, an
     * exception will be thrown.
     * 
     * @param password the password to perform the integrity check.
     * @throws UnrecoverableKeyException if the check failed because of a wrong password.
     * @throws IOException if fields can not be processed.
     * @throws NoSuchAlgorithmException if the ciphering algorithm is unkown.
     * @throws InvalidKeySpecException if the {@code iv} field is malformed.
     */
    public void checkIntegrity(char[] password) throws UnrecoverableKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        try
        {
            SecretKey secret = CryptoTools.getAESSecretKey(password, getSalt());
            MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
            byte[] data = CryptoTools.decipherData(getCipheredData(), secret, getIV());
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
