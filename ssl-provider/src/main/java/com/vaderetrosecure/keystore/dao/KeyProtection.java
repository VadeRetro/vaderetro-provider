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
    private byte[] cipheredKeyProtection;
    
    public KeyProtection()
    {
        this("", new byte[]{}, new byte[]{});
    }
    
    public KeyProtection(String alias, byte[] iv, byte[] cipheredKeyProtection)
    {
        this.alias = alias;
        this.iv = iv;
        this.cipheredKeyProtection = cipheredKeyProtection;
    }
    
    public KeyProtection(String alias, byte[] iv, SecretKey key, PrivateKey privateKey)
    {
        this.alias = alias;
        this.iv = iv;
        try
        {
            setKeyProtection(key, privateKey);
        }
        catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            
            this.cipheredKeyProtection = new byte[]{};
        }
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

    public byte[] getCipheredKeyProtection()
    {
        return cipheredKeyProtection;
    }

    public void setCipheredKeyProtection(byte[] cipheredKeyProtection)
    {
        this.cipheredKeyProtection = cipheredKeyProtection;
    }
    
    public SecretKey getKeyProtection(PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        return new SecretKeySpec(CipheringTools.decipherData(getCipheredKeyProtection(), publicKey), "AES");
    }
    
    public void setKeyProtection(SecretKey keyProtection, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        setCipheredKeyProtection(CipheringTools.cipherData(keyProtection.getEncoded(), privateKey));
    }
    
    public static SecretKey generateSecretKey(char[] keyPassword, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        return CipheringTools.getAESSecretKey(keyPassword, salt);
    }
}
