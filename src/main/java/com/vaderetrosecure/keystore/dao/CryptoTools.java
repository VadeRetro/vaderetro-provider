/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * @author ahonore
 *
 */
class CryptoTools
{
    public static SecretKey getAESSecretKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
    
    public static String b64Encode(byte[] data)
    {
        if (data == null)
            return "";
        
        return new String(Base64.getEncoder().encode(data), StandardCharsets.US_ASCII);
    }
    
    public static byte[] b64Decode(String data)
    {
        if (data == null)
            return "".getBytes(StandardCharsets.US_ASCII);
        
        return Base64.getDecoder().decode(data.getBytes(StandardCharsets.US_ASCII));
    }
    
    public static String hexStringEncode(byte[] data)
    {
        if (data == null)
            return "";
        
        return DatatypeConverter.printHexBinary(data).toLowerCase();
    }
    
    public static byte[] hexStringDecode(String data)
    {
        if (data == null)
            return "".getBytes(StandardCharsets.US_ASCII);
        
        return DatatypeConverter.parseHexBinary(data);
    }
}
