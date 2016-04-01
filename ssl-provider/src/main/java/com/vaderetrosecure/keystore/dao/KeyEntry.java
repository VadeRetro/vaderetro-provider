/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author ahonore
 *
 */
public class KeyEntry extends KeyStoreEntry
{
    private String algorithm;
    private byte[] cipheredKey;
    private LockedKeyProtection lockedKeyProtection;

    public KeyEntry()
    {
        super();
        this.algorithm = null;
        this.cipheredKey = new byte[]{};
        this.lockedKeyProtection = null;
    }

    public KeyEntry(String alias, Date creationDate, String algorithm, byte[] cipheredKey, LockedKeyProtection lockedKeyProtection)
    {
        super(alias, creationDate);
        this.algorithm = algorithm;
        this.cipheredKey = cipheredKey;
        this.lockedKeyProtection = lockedKeyProtection;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public byte[] getCipheredKey()
    {
        return cipheredKey;
    }

    public void setCipheredKey(byte[] cipheredKey)
    {
        this.cipheredKey = cipheredKey;
    }

    public LockedKeyProtection getLockedKeyProtection()
    {
        return lockedKeyProtection;
    }

    public void setLockedKeyProtection(LockedKeyProtection lockedKeyProtection)
    {
        this.lockedKeyProtection = lockedKeyProtection;
    }

    public Key getKey(KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        return null;
    }

    public void setKey(Key key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
    }
}
