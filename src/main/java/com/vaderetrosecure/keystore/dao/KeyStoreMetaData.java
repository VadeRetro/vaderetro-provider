/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
public class KeyStoreMetaData
{
    private static final Logger LOG = Logger.getLogger(KeyStoreMetaData.class);
    
    public static final int KEYSTORE_MAJOR_VERSION = 1;
    public static final String KEYSTORE_VERSION = "1.0.0";
    
    private static final SecureRandom random = new SecureRandom();

    private int majorVersion;
    private String version;
    private byte[] salt;
    private byte[] iv;
    private byte[] keyIV;
    private byte[] keyIVHash;
    
    private SecretKey masterKey;
    
    public KeyStoreMetaData()
    {
        this(0, "", new byte[]{}, new byte[]{}, new byte[]{}, new byte[]{});
    }

    public KeyStoreMetaData(int majorVersion, String version, byte[] salt, byte[] iv, byte[] keyIV, byte[] keyIVHash)
    {
        setMajorVersion(majorVersion);
        setVersion(version);
        setSalt(salt);
        setIV(iv);
        setKeyIV(keyIV);
        setKeyIVHash(keyIVHash);

        masterKey = null;
    }

    public int getMajorVersion()
    {
        return majorVersion;
    }

    public void setMajorVersion(int majorVersion)
    {
        this.majorVersion = majorVersion;
    }

    public String getVersion()
    {
        return version;
    }

    public void setVersion(String version)
    {
        this.version = version;
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

    public byte[] getKeyIV()
    {
        return keyIV;
    }

    public void setKeyIV(byte[] keyIV)
    {
        this.keyIV = keyIV;
    }

    public byte[] getKeyIVHash()
    {
        return keyIVHash;
    }

    public void setKeyIVHash(byte[] keyIVHash)
    {
        this.keyIVHash = keyIVHash;
    }
    
    public static KeyStoreMetaData generate(char[] password) throws GeneralSecurityException, UnrecoverableKeyException
    {
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] keyIVData = new byte[16];
        random.nextBytes(keyIVData);

        byte[] iv = new byte[16];
        random.nextBytes(iv);

        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        byte[] sha2keyIVData = sha2.digest(keyIVData);
        SecretKey secret = CipheringTools.getAESSecretKey(password, salt);
        byte[] cipheredKeyIVData = CipheringTools.cipherData(keyIVData, secret, iv);

        return new KeyStoreMetaData(KEYSTORE_MAJOR_VERSION, KEYSTORE_VERSION, salt, iv, cipheredKeyIVData, sha2keyIVData);
    }
    
    public void checkIntegrity(char[] masterPassword) throws UnrecoverableKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        if ((KEYSTORE_MAJOR_VERSION != getMajorVersion()) || !KEYSTORE_VERSION.equals(getVersion()))
            throw new IOException("bad version: expected " + KEYSTORE_VERSION);
        
        // create secret key to decipher 
        try
        {
            MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
            masterKey = CipheringTools.getAESSecretKey(masterPassword, getSalt());
            byte[] rawKeyIV = CipheringTools.decipherData(getKeyIV(), masterKey, getIV());
            if (!Arrays.equals(getKeyIVHash(), sha2.digest(rawKeyIV)))
                throw new UnrecoverableKeyException("integrity check failed");
        }
        catch (InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            LOG.fatal(e, e);
            throw new UnrecoverableKeyException("integrity check failed");
        }
    }
    
    public byte[] cipherKeyEntry(char[] keyPassword, byte[] rawKeyEntry) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey secret = CipheringTools.getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = CipheringTools.decipherData(getKeyIV(), masterKey, getIV());
        return CipheringTools.cipherData(rawKeyEntry, secret, rawKeyIV);
    }
    
    public byte[] decipherKeyEntry(char[] keyPassword, byte[] cipheredKeyEntry) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey secret = CipheringTools.getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = CipheringTools.decipherData(getKeyIV(), masterKey, getIV());
        return CipheringTools.decipherData(cipheredKeyEntry, secret, rawKeyIV);
    }
}
