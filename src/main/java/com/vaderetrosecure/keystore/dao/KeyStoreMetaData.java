/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
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
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
    private String salt;
    private String iv;
    private String keyIV;
    private String keyIVHash;
    
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
        return CryptoTools.b64Decode(salt);
    }

    public void setSalt(byte[] salt)
    {
        this.salt = CryptoTools.b64Encode(salt);
    }

    public byte[] getIV()
    {
        return CryptoTools.b64Decode(iv);
    }

    public void setIV(byte[] iv)
    {
        this.iv = CryptoTools.b64Encode(iv);
    }

    public byte[] getKeyIV()
    {
        return CryptoTools.b64Decode(keyIV);
    }

    public void setKeyIV(byte[] keyIV)
    {
        this.keyIV = CryptoTools.b64Encode(keyIV);
    }

    public byte[] getKeyIVHash()
    {
        return CryptoTools.hexStringDecode(keyIVHash);
    }

    public void setKeyIVHash(byte[] keyIVHash)
    {
        this.keyIVHash = CryptoTools.hexStringEncode(keyIVHash);
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
        SecretKey secret = CryptoTools.getAESSecretKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DigestOutputStream dos = new DigestOutputStream(new CipherOutputStream(baos, cipher), sha2))
        {
            dos.write(keyIVData);
        }
        catch (IOException e)
        {
            LOG.fatal(e, e);
            throw new UnrecoverableKeyException(e.getMessage());
        }

        return new KeyStoreMetaData(KEYSTORE_MAJOR_VERSION, KEYSTORE_VERSION, salt,  iv, baos.toByteArray(), sha2.digest());
    }
    
    public void checkIntegrity(char[] masterPassword) throws UnrecoverableKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        if ((KEYSTORE_MAJOR_VERSION != getMajorVersion()) || !KEYSTORE_VERSION.equals(getVersion()))
            throw new IOException("bad version: expected " + KEYSTORE_VERSION);
        
        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        
        // create secret key to decipher 
        masterKey = CryptoTools.getAESSecretKey(masterPassword, getSalt());
        byte[] rawKeyIV;
        try
        {
            rawKeyIV = getDecipheredKeyIV();
            if (!Arrays.equals(getKeyIVHash(), sha2.digest(rawKeyIV)))
                throw new UnrecoverableKeyException("integrity check failed");
        }
        catch (InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            LOG.fatal(e, e);
            throw new UnrecoverableKeyException("integrity check failed");
        }
    }
    
    public byte[] cipherKey(char[] keyPassword, byte[] rawKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // 10 bytes of salt will be added at the beginning of the key
        byte[] keySalt = new byte[10];
        random.nextBytes(keySalt);
        
        byte[] cipherKey = new byte[keySalt.length + rawKey.length];
        System.arraycopy(keySalt, 0, cipherKey, 0, keySalt.length);
        System.arraycopy(rawKey, 0, cipherKey, keySalt.length, rawKey.length);
        
        SecretKey secret = CryptoTools.getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = getDecipheredKeyIV();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(rawKeyIV));
        return cipher.doFinal(cipherKey);
    }
    
    public byte[] decipherKey(char[] keyPassword, byte[] cipheredKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // 10 bytes of salt will be removed from the beginning of the key
        SecretKey secret = CryptoTools.getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = getDecipheredKeyIV();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(rawKeyIV));
        byte[] saltedKey = cipher.doFinal(cipheredKey);
        return Arrays.copyOfRange(saltedKey, 10, saltedKey.length);
    }
    
    private byte[] getDecipheredKeyIV() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, masterKey, new IvParameterSpec(getIV()));
        return cipher.doFinal(getKeyIV());
    }
}
