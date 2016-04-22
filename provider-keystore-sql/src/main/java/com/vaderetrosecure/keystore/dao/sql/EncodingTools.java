/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;

/**
 * This class provides helper methods to encode/decode data to or from the store.
 * It is useful for storing arrays of bytes from {@code KeyStoreEntry} objects as strings in the database. 
 * 
 * @author ahonore
 * @see com.vaderetrosecure.keystore.dao.KeyStoreEntry
 */
final class EncodingTools
{
    private static final Logger LOG = Logger.getLogger(EncodingTools.class);

    private static final Lock LOCK = new ReentrantLock();
    private static MessageDigest SHA2_DIGEST;
    static
    {
        try
        {
            SHA2_DIGEST = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
        }
    }
    
    private EncodingTools()
    {
    }
    
    /**
     * Encode an array of bytes into a Base64 string.
     * 
     * @param data the array of bytes to encode.
     * @return a Base64 encoded string. 
     */
    public static String b64Encode(byte[] data)
    {
        if (data == null)
            return "";
        
        return new String(Base64.getEncoder().encode(data), StandardCharsets.US_ASCII);
    }
    
    /**
     * Decode a Base64 encoded string into an array of bytes. 
     * 
     * @param data the Base64 encoded string.
     * @return an array of bytes.
     */
    public static byte[] b64Decode(String data)
    {
        if (data == null)
            return "".getBytes(StandardCharsets.US_ASCII);
        
        return Base64.getDecoder().decode(data.getBytes(StandardCharsets.US_ASCII));
    }
    
    /**
     * Encode an array of bytes as a hexadecimal string.
     * 
     * @param data the array of bytes to encode.
     * @return a hexadecimal encoded string. 
     */
    public static String hexStringEncode(byte[] data)
    {
        if (data == null)
            return "";
        
        return DatatypeConverter.printHexBinary(data).toLowerCase();
    }
    
    /**
     * Decode a hexadecimal encoded string into an array of bytes. 
     * 
     * @param data the hexadecimal encoded string.
     * @return an array of bytes.
     */
    public static byte[] hexStringDecode(String data)
    {
        if (data == null)
            return "".getBytes(StandardCharsets.US_ASCII);
        
        return DatatypeConverter.parseHexBinary(data);
    }
    
    /**
     * Get the SHA-256 string from a string.
     * The hash string is encoded in hexadecimal.
     * 
     * @param data the string to hash.
     * @return the SHA-256 hash as a hexadecimal string.
     */
    public static String toSHA2(String data)
    {
        LOCK.lock();
        try
        {
            return DatatypeConverter.printHexBinary(SHA2_DIGEST.digest(data.getBytes(StandardCharsets.UTF_8))).toLowerCase();
        }
        finally
        {
            LOCK.unlock();
        }
    }
}
