/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
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
abstract class KeyEntry
{
    private String alias;
    private Date creationDate;
    private String algorithm;
    private byte[] cipheredKey;

    public KeyEntry()
    {
        this("", 0, Date.from(Instant.now()), "", new byte[]{});
    }

    public KeyEntry(String alias, int rank, Date creationDate, String algorithm, byte[] cipheredKey)
    {
        this.alias = alias;
        this.creationDate = creationDate;
        this.algorithm = algorithm;
        this.cipheredKey = cipheredKey;
    }

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

    public abstract Key getKey(KeyProtection keyProtection, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;

    public abstract Key getKey(char[] password, byte[] salt, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;
}
