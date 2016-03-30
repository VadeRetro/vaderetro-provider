/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

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
    @Override
    public SecretKey getKey(KeyProtection keyProtection, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        return new SecretKeySpec(CipheringTools.decipherData(getCipheredKey(), keyProtection.getKeyProtection(publicKey), keyProtection.getIV()), getAlgorithm());
    }

    @Override
    public SecretKey getKey(char[] password, byte[] salt, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        return new SecretKeySpec(CipheringTools.decipherData(getCipheredKey(), CipheringTools.getAESSecretKey(password, salt), iv), getAlgorithm());
    }
}
