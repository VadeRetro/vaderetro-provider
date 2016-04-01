/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author ahonore
 *
 */
public class PrivateKeyEntry extends KeyEntry
{
    public PrivateKeyEntry(String alias, Date creationDate, PrivateKey key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        super(alias, creationDate, key.getAlgorithm(), null, null);
        setKey(key, keyProtection);
    }

    @Override
    public PrivateKey getKey(KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
        byte[] encKey = CipheringTools.decipherData(getCipheredKey(), keyProtection.getKey(), keyProtection.getIV());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encKey));
    }

    @Override
    public void setKey(Key key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setCipheredKey(CipheringTools.cipherData(key.getEncoded(), keyProtection.getKey(), keyProtection.getIV()));
    }
}
