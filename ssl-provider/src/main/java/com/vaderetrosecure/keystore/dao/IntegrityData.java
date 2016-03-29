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
public class IntegrityData
{
    private static final Logger LOG = Logger.getLogger(IntegrityData.class);
    
//    public static final int KEYSTORE_MAJOR_VERSION = 1;
//    public static final String KEYSTORE_VERSION = "1.0.0";
    
    private static final SecureRandom random = new SecureRandom();

//    private int majorVersion;
//    private String version;
    private byte[] salt;
    private byte[] iv;
    private byte[] cipheredkeyPasswordSalt;
    private byte[] keyPasswordSaltHash;
    
    public IntegrityData()
    {
        this(/*0, "",*/ new byte[]{}, new byte[]{}, new byte[]{}, new byte[]{});
    }

    public IntegrityData(/*int majorVersion, String version,*/ byte[] salt, byte[] iv, byte[] cipheredkeyPasswordSalt, byte[] keyPasswordSaltHash)
    {
//        setMajorVersion(majorVersion);
//        setVersion(version);
        setSalt(salt);
        setIV(iv);
        setCipheredkeyPasswordSalt(cipheredkeyPasswordSalt);
        setKeyPasswordSaltHash(keyPasswordSaltHash);
    }

//    public int getMajorVersion()
//    {
//        return majorVersion;
//    }
//
//    public void setMajorVersion(int majorVersion)
//    {
//        this.majorVersion = majorVersion;
//    }
//
//    public String getVersion()
//    {
//        return version;
//    }
//
//    public void setVersion(String version)
//    {
//        this.version = version;
//    }

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

    public byte[] getCipheredkeyPasswordSalt()
    {
        return cipheredkeyPasswordSalt;
    }

    public void setCipheredkeyPasswordSalt(byte[] cipheredkeyPasswordSalt)
    {
        this.cipheredkeyPasswordSalt = cipheredkeyPasswordSalt;
    }

    public byte[] getKeyPasswordSaltHash()
    {
        return keyPasswordSaltHash;
    }

    public void setKeyPasswordSaltHash(byte[] keyPasswordSaltHash)
    {
        this.keyPasswordSaltHash = keyPasswordSaltHash;
    }
    
    public static IntegrityData generate(char[] password) throws GeneralSecurityException, UnrecoverableKeyException
    {
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] keyPasswordSalt = new byte[16];
        random.nextBytes(keyPasswordSalt);

        byte[] iv = new byte[16];
        random.nextBytes(iv);

        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        byte[] keyPasswordSaltHash = sha2.digest(keyPasswordSalt);
        SecretKey secret = CipheringTools.getAESSecretKey(password, salt);
        byte[] cipheredkeyPasswordSalt = CipheringTools.cipherData(keyPasswordSalt, secret, iv);

        return new IntegrityData(/*KEYSTORE_MAJOR_VERSION, KEYSTORE_VERSION,*/ salt, iv, cipheredkeyPasswordSalt, keyPasswordSaltHash);
    }
    
    public SecretKey getMasterKey(char[] masterPassword) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        return CipheringTools.getAESSecretKey(masterPassword, getSalt());
    }
    
    public void checkIntegrity(char[] masterPassword) throws UnrecoverableKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
//        if ((KEYSTORE_MAJOR_VERSION != getMajorVersion()) || !KEYSTORE_VERSION.equals(getVersion()))
//            throw new IOException("bad version: expected " + KEYSTORE_VERSION);
        
        // create secret key to decipher 
        try
        {
            MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
            SecretKey masterKey = getMasterKey(masterPassword);
            byte[] keyPasswordSalt = CipheringTools.decipherData(getCipheredkeyPasswordSalt(), masterKey, getIV());
            if (!Arrays.equals(getKeyPasswordSaltHash(), sha2.digest(keyPasswordSalt)))
                throw new UnrecoverableKeyException("integrity check failed");
        }
        catch (InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
            throw new UnrecoverableKeyException("integrity check failed");
        }
    }
    
    public byte[] getKeyPasswordSalt(SecretKey masterKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        return CipheringTools.decipherData(getCipheredkeyPasswordSalt(), masterKey, getIV());
    }
    
    public byte[] cipherKeyEntry(char[] keyPassword, byte[] rawKeyEntry) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey secret = CipheringTools.getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = CipheringTools.decipherData(getCipheredkeyPasswordSalt(), masterKey, getIV());
        return CipheringTools.cipherData(rawKeyEntry, secret, rawKeyIV);
    }
    
    public byte[] decipherKeyEntry(char[] keyPassword, byte[] cipheredKeyEntry) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey secret = CipheringTools.getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = CipheringTools.decipherData(getCipheredkeyPasswordSalt(), masterKey, getIV());
        return CipheringTools.decipherData(cipheredKeyEntry, secret, rawKeyIV);
    }
}
