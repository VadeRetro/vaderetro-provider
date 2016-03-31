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
    private byte[] cipheredData;
    private byte[] dataHash;
    
    public IntegrityData()
    {
        this(/*0, "",*/ new byte[]{}, new byte[]{}, new byte[]{}, new byte[]{});
    }

    public IntegrityData(/*int majorVersion, String version,*/ byte[] salt, byte[] iv, byte[] cipheredData, byte[] dataHash)
    {
//        setMajorVersion(majorVersion);
//        setVersion(version);
        setSalt(salt);
        setIV(iv);
        setCipheredData(cipheredData);
        setDataHash(dataHash);
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
    
    public static IntegrityData generate(char[] password) throws GeneralSecurityException, UnrecoverableKeyException
    {
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] integrityData = new byte[64];
        random.nextBytes(integrityData);

        byte[] iv = new byte[16];
        random.nextBytes(iv);

        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        byte[] integrityDataHash = sha2.digest(integrityData);
        SecretKey secret = CipheringTools.getAESSecretKey(password, salt);
        byte[] cipheredIntegrityData = CipheringTools.cipherData(integrityData, secret, iv);

        return new IntegrityData(/*KEYSTORE_MAJOR_VERSION, KEYSTORE_VERSION,*/ salt, iv, cipheredIntegrityData, integrityDataHash);
    }
    
    public SecretKey getMasterKey(char[] masterPassword) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        return CipheringTools.getAESSecretKey(masterPassword, getSalt());
    }
    
    public void checkIntegrity(SecretKey masterKey) throws UnrecoverableKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
//        if ((KEYSTORE_MAJOR_VERSION != getMajorVersion()) || !KEYSTORE_VERSION.equals(getVersion()))
//            throw new IOException("bad version: expected " + KEYSTORE_VERSION);
        
        // create secret key to decipher 
        try
        {
            MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
            byte[] data = CipheringTools.decipherData(getCipheredData(), masterKey, getIV());
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
