/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.xml.bind.DatatypeConverter;

/**
 * @author ahonore
 *
 */
class EncodingTools
{
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
