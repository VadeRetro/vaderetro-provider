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
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

/**
 * @author ahonore
 *
 */
final class EncodingTools
{
    private final static Logger LOG = Logger.getLogger(EncodingTools.class);

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
