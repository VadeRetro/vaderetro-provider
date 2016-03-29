/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author ahonore
 *
 */
public class KeyProtection
{
    private byte[] iv;
    private byte[] cipheredKeyProtection;
    
    public KeyProtection()
    {
        this(new byte[]{}, new byte[]{});
    }
    
    public KeyProtection(byte[] iv, byte[] cipheredKeyProtection)
    {
        this.iv = iv;
        this.cipheredKeyProtection = cipheredKeyProtection;
    }

    public byte[] getIv()
    {
        return iv;
    }

    public void setIv(byte[] iv)
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
    
    public static SecretKey generateSecretKey()
    {
        return null;
    }
}
