/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
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
import javax.crypto.CipherInputStream;
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

    private int majorVersion;
    private String version;
    private String salt;
    private String iv;
    private String data;
    private String dataHash;
    
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
        this.data = data;
        this.dataHash = dataHash;
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

    public String getData()
    {
        return data;
    }

    public void setData(String data)
    {
        this.data = data;
    }

    public String getDataHash()
    {
        return dataHash;
    }

    public void setDataHash(String dataHash)
    {
        this.dataHash = dataHash;
    }
    
    public static KeyStoreMetaData generate(char[] password) throws GeneralSecurityException, UnrecoverableKeyException
    {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        byte[] data = new byte[128];
        sr.nextBytes(data);

        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        Encoder b64Enc = Base64.getEncoder();
        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        SecretKey secret = getAESSecretKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DigestOutputStream dos = new DigestOutputStream(new CipherOutputStream(baos, cipher), sha2))
        {
            dos.write(data);
        }
        catch (IOException e)
        {
            LOG.fatal(e, e);
            throw new UnrecoverableKeyException(e.getMessage());
        }

        LOG.debug("data: " + DatatypeConverter.printHexBinary(data));
        return new KeyStoreMetaData(KEYSTORE_MAJOR_VERSION, KEYSTORE_VERSION, new String(b64Enc.encode(salt), StandardCharsets.US_ASCII), 
                new String(b64Enc.encode(iv), StandardCharsets.US_ASCII), 
                new String(b64Enc.encode(baos.toByteArray()), StandardCharsets.US_ASCII),
                new String(DatatypeConverter.printHexBinary(sha2.digest()).toLowerCase()));
    }
    
    public void checkIntegrity(char[] password) throws UnrecoverableKeyException, GeneralSecurityException, IOException
    {
        if ((KEYSTORE_MAJOR_VERSION != getMajorVersion()) || !KEYSTORE_VERSION.equals(getVersion()))
            throw new IOException("bad version: expected " + KEYSTORE_VERSION);
        
        Decoder b64Dec = Base64.getDecoder();
        MessageDigest sha2 = MessageDigest.getInstance("SHA-256");
        
        // create secret key to decipher 
        SecretKey secret = getAESSecretKey(password, b64Dec.decode(salt.getBytes(StandardCharsets.US_ASCII)));
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(b64Dec.decode(iv.getBytes(StandardCharsets.US_ASCII))));
        byte[] dataBytes = b64Dec.decode(data.getBytes(StandardCharsets.US_ASCII));
        byte[] outBytes = new byte[dataBytes.length * 2]; // to be sure to read all bytes in one call
        try (DigestInputStream dis = new DigestInputStream(new CipherInputStream(new ByteArrayInputStream(dataBytes), cipher), sha2))
        {
            dis.read(outBytes);
        }
        catch (IOException e)
        {
            LOG.fatal(e, e);
            throw new UnrecoverableKeyException(e.getMessage());
        }
        
        LOG.debug("data: " + DatatypeConverter.printHexBinary(outBytes));
        if (!Arrays.equals(DatatypeConverter.parseHexBinary(dataHash), sha2.digest()))
            throw new UnrecoverableKeyException("integrity check failed");
    }
    
    private static SecretKey getAESSecretKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
    
    public Cipher getKeyCipherer()
    {
        return null;
    }
    
    public Cipher getKeyDecipherer()
    {
        return null;
    }
}
