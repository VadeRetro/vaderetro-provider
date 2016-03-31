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
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author ahonore
 *
 */
public class SecretKeyEntry extends KeyEntry
{
    public SecretKeyEntry(String alias, Date creationDate, SecretKey key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        super(alias, creationDate, key.getAlgorithm(), null);
        setKey(key, keyProtection);
    }

    @Override
    public SecretKey getKey(KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        return new SecretKeySpec(CipheringTools.decipherData(getCipheredKey(), keyProtection.getKey(), keyProtection.getIV()), getAlgorithm());
    }

    @Override
    public void setKey(Key key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setCipheredKey(CipheringTools.cipherData(key.getEncoded(), keyProtection.getKey(), keyProtection.getIV()));
    }
}
