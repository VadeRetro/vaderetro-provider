/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author ahonore
 *
 */
final class CipheringTools
{
    private CipheringTools()
    {
    }
    
    public static byte[] cipherData(SecretKey aesSecretKey, byte[] iv, byte[] rawData) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // 10 bytes of salt will be added at the beginning of the key
        byte[] keySalt = new byte[10];
        random.nextBytes(keySalt);
        
        byte[] cipherKey = new byte[keySalt.length + rawData.length];
        System.arraycopy(keySalt, 0, cipherKey, 0, keySalt.length);
        System.arraycopy(rawData, 0, cipherKey, keySalt.length, rawData.length);
        
        SecretKey secret = getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = getDecipheredKeyIV();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(rawKeyIV));
        return cipher.doFinal(cipherKey);
    }
    
    public byte[] decipherData(SecretKey aesSecretKey, byte[] iv, byte[] cipheredData) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // 10 bytes of salt will be removed from the beginning of the key
        SecretKey secret = getAESSecretKey(keyPassword, getSalt());
        byte[] rawKeyIV = getDecipheredKeyIV();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(rawKeyIV));
        byte[] saltedKey = cipher.doFinal(cipheredData);
        return Arrays.copyOfRange(saltedKey, 10, saltedKey.length);
    }

    public static SecretKey getAESSecretKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
}
