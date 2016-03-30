/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author ahonore
 *
 */
public class PrivateKeyEntry extends KeyEntry
{
    @Override
    public PrivateKey getKey(KeyProtection keyProtection, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
        byte[] encKey = CipheringTools.decipherData(getCipheredKey(), keyProtection.getKeyProtection(publicKey), keyProtection.getIV());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encKey));
    }

    @Override
    public PrivateKey getKey(char[] password, byte[] salt, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
        byte[] encKey = CipheringTools.decipherData(getCipheredKey(), CipheringTools.getAESSecretKey(password, salt), iv);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encKey));
    }
}
