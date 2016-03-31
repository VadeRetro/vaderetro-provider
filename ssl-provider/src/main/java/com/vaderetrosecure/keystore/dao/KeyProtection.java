/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

/**
 * @author ahonore
 *
 */
public class KeyProtection
{
    private final static Logger LOG = Logger.getLogger(KeyProtection.class);

    private String alias;
    private byte[] iv;
    private SecretKey key;
    
    public KeyProtection()
    {
        this("", new byte[]{}, null);
    }
    
    public KeyProtection(String alias, byte[] iv, SecretKey key)
    {
        this.alias = alias;
        this.iv = iv;
        this.key = key;
    }
    
    public KeyProtection(LockedKeyProtection lockedKeyProtection, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        this.alias = lockedKeyProtection.getAlias();
        this.iv = lockedKeyProtection.getIV();
        this.key = new SecretKeySpec(CipheringTools.decipherData(lockedKeyProtection.getCipheredKey(), publicKey), "AES");
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public byte[] getIV()
    {
        return iv;
    }

    public void setIV(byte[] iv)
    {
        this.iv = iv;
    }

    public SecretKey getKey()
    {
        return key;
    }

    public void setKey(SecretKey key)
    {
        this.key = key;
    }
    
    public static KeyProtection generateKeyProtection(String alias, char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] iv = CipheringTools.generateIV();
        return generateKeyProtection(alias, password, salt, iv);
    }
    
    public static KeyProtection generateKeyProtection(String alias, char[] password, byte[] salt, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKey sk = CipheringTools.getAESSecretKey(password, salt);
        return new KeyProtection(alias, iv, sk);
    }
    
    public LockedKeyProtection getLockedKeyProtection(PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        return new LockedKeyProtection(getAlias(), getIV(), CipheringTools.cipherData(getKey().getEncoded(), privateKey));
    }
}
