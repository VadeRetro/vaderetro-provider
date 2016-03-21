/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Lock LOCK = new ReentrantLock();
    
    private CipheringTools()
    {
    }
    
    public static byte[] cipherData(byte[] rawData, SecretKey aesSecretKey, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // 16 bytes of salt will be added at the beginning of the key
        byte[] dataSalt = new byte[16];
        LOCK.lock();
        try
        {
            RANDOM.nextBytes(dataSalt);
        }
        finally
        {
            LOCK.unlock();
        }
        
        byte[] cipherKey = new byte[dataSalt.length + rawData.length];
        System.arraycopy(dataSalt, 0, cipherKey, 0, dataSalt.length);
        System.arraycopy(rawData, 0, cipherKey, dataSalt.length, rawData.length);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesSecretKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherKey);
    }
    
    public static byte[] decipherData(byte[] cipheredData, SecretKey aesSecretKey, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // 16 bytes of salt will be removed from the beginning of the key
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesSecretKey, new IvParameterSpec(iv));
        byte[] saltedData = cipher.doFinal(cipheredData);
        return Arrays.copyOfRange(saltedData, 16, saltedData.length);
    }

    public static SecretKey getAESSecretKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
}
