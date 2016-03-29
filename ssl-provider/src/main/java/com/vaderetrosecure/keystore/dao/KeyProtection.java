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
    
    public byte[] getKeyProtection(PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        return CipheringTools.decipherData(getCipheredKeyProtection(), publicKey);
    }
    
    public void setKeyProtection(byte[] keyProtection, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        setCipheredKeyProtection(CipheringTools.cipherData(keyProtection, privateKey));
    }
    
    public static SecretKey generateSecretKey()
    {
        return null;
    }
}
