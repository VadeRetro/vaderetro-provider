/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;

/**
 * @author ahonore
 *
 */
public class KeyStoreMetaData
{
    private final static Logger LOG = Logger.getLogger(KeyStoreMetaData.class);
    
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
        this(0, "", "", "", "", "");
    }

    public KeyStoreMetaData(int majorVersion,String version, String salt, String iv, String data, String dataHash)
    {
        this.majorVersion = majorVersion;
        this.version = version;
        this.salt = salt;
        this.iv = iv;
        this.keyIV = data;
        this.keyIVHash = dataHash;
        
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

    public String getSalt()
    {
        return salt;
    }

    public void setSalt(String salt)
    {
        this.salt = salt;
    }

    public String getIV()
    {
        return iv;
    }

    public void setIV(String iv)
    {
        this.iv = iv;
    }

    public String getKeyIV()
    {
        return keyIV;
    }

    public void setKeyIV(String data)
    {
        this.keyIV = data;
    }

    public String getKeyIVHash()
    {
        return keyIVHash;
    }

    public void setKeyIVHash(String dataHash)
    {
        this.keyIVHash = dataHash;
    }
    
    public static KeyStoreMetaData generate(char[] password) throws GeneralSecurityException, UnrecoverableKeyException
    {
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] keyIVData = new byte[16];
        random.nextBytes(keyIVData);

        byte[] iv = new byte[16];
        random.nextBytes(iv);

        Encoder b64Enc = Base64.getEncoder();
        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        SecretKey secret = getAESSecretKey(password, salt);
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

        LOG.debug("data: " + DatatypeConverter.printHexBinary(keyIVData));
        return new KeyStoreMetaData(KEYSTORE_MAJOR_VERSION, KEYSTORE_VERSION, new String(b64Enc.encode(salt), StandardCharsets.US_ASCII), 
                new String(b64Enc.encode(iv), StandardCharsets.US_ASCII), 
                new String(b64Enc.encode(baos.toByteArray()), StandardCharsets.US_ASCII),
                new String(DatatypeConverter.printHexBinary(sha2.digest()).toLowerCase()));
    }
    
    public void checkIntegrity(char[] masterPassword) throws UnrecoverableKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        if ((KEYSTORE_MAJOR_VERSION != getMajorVersion()) || !KEYSTORE_VERSION.equals(getVersion()))
            throw new IOException("bad version: expected " + KEYSTORE_VERSION);
        
        Decoder b64Dec = Base64.getDecoder();
        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        
        // create secret key to decipher 
        masterKey = getAESSecretKey(masterPassword, b64Dec.decode(salt.getBytes(StandardCharsets.US_ASCII)));
        byte[] rawKeyIV;
        try
        {
            rawKeyIV = getDecipheredKeyIV();
            LOG.debug("data: " + DatatypeConverter.printHexBinary(rawKeyIV));
            if (!Arrays.equals(DatatypeConverter.parseHexBinary(keyIVHash), sha2.digest(rawKeyIV)))
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
        
        Decoder b64Dec = Base64.getDecoder();
        SecretKey secret = getAESSecretKey(keyPassword, b64Dec.decode(salt.getBytes(StandardCharsets.US_ASCII)));
        byte[] rawKeyIV = getDecipheredKeyIV();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(rawKeyIV));
        return cipher.doFinal(cipherKey);
    }
    
    public byte[] decipherKey(char[] keyPassword, byte[] cipheredKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // 10 bytes of salt will be removed from the beginning of the key
        Decoder b64Dec = Base64.getDecoder();
        SecretKey secret = getAESSecretKey(keyPassword, b64Dec.decode(salt.getBytes(StandardCharsets.US_ASCII)));
        byte[] rawKeyIV = getDecipheredKeyIV();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(rawKeyIV));
        byte[] saltedKey = cipher.doFinal(cipheredKey);
        return Arrays.copyOfRange(saltedKey, 10, saltedKey.length);
    }
    
    private byte[] getDecipheredKeyIV() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        Decoder b64Dec = Base64.getDecoder();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, masterKey, new IvParameterSpec(b64Dec.decode(iv.getBytes(StandardCharsets.US_ASCII))));
        return cipher.doFinal(b64Dec.decode(keyIV.getBytes(StandardCharsets.US_ASCII)));
    }
    
    private static SecretKey getAESSecretKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
}
