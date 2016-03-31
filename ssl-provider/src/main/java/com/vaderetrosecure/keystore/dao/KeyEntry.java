/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author ahonore
 *
 */
public abstract class KeyEntry
{
    private String alias;
    private Date creationDate;
    private String algorithm;
    private byte[] cipheredKey;
    private LockedKeyProtection lockedKeyProtection;

    public KeyEntry()
    {
        this("", Date.from(Instant.now()), "", new byte[]{}, null);
    }

    public KeyEntry(String alias, Date creationDate, String algorithm, byte[] cipheredKey, LockedKeyProtection lockedKeyProtection)
    {
        this.alias = alias;
        this.creationDate = creationDate;
        this.algorithm = algorithm;
        this.cipheredKey = cipheredKey;
        this.lockedKeyProtection = lockedKeyProtection;
    }

//    public KeyEntry(String alias, Date creationDate, Key key, char[] password, byte[] salt, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
//    {
//        this.alias = alias;
//        this.creationDate = creationDate;
//        this.algorithm = key.getAlgorithm();
//        setKey(key, password, salt, iv);
//    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public Date getCreationDate()
    {
        return creationDate;
    }

    public void setCreationDate(Date creationDate)
    {
        this.creationDate = creationDate;
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

    public abstract Key getKey(KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;

    public abstract void setKey(Key key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;
}
