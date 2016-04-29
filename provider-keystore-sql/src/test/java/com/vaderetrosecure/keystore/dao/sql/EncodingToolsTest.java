/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

/**
 * 
 */
public class EncodingToolsTest
{
    private static final String stringData0 = "^#chaîne à tester !~";
    private static final String stringData0Base64 = "XiNjaGHDrm5lIMOgIHRlc3RlciAhfg==";
    private static final String stringData0Hexa = "5e23636861c3ae6e6520c3a02074657374657220217e";
    private static final String stringData0HashHexa = "db131777efdc2ad5397822e7ceb2c8e12c645cbf7890a77f46fc428e412148ad";
    private static final String stringData1 = "学校";
    private static final String stringData1Base64 = "5a2m5qCh";
    private static final String stringData1Hexa = "e5ada6e6a0a1";
    private static final String stringData1HashHexa = "dc6e2aafeb9e125b69d1b143f05c66414e6e1a4f46c163a52a6d289efeef27c7";

    @Test
    public void testB64Encode()
    {
        Assert.assertEquals("", EncodingTools.b64Encode(null)); ;
        Assert.assertEquals("", EncodingTools.b64Encode("".getBytes(StandardCharsets.US_ASCII))); ;
        Assert.assertEquals(stringData0Base64, EncodingTools.b64Encode(stringData0.getBytes(StandardCharsets.UTF_8))); ;
        Assert.assertEquals(stringData1Base64, EncodingTools.b64Encode(stringData1.getBytes(StandardCharsets.UTF_8))); ;
    }

    @Test
    public void testB64Decode()
    {
        Assert.assertArrayEquals("".getBytes(StandardCharsets.US_ASCII), EncodingTools.b64Decode(null)); ;
        Assert.assertArrayEquals("".getBytes(StandardCharsets.US_ASCII), EncodingTools.b64Decode("")); ;
        Assert.assertArrayEquals(stringData0.getBytes(StandardCharsets.UTF_8), EncodingTools.b64Decode(stringData0Base64)); ;
        Assert.assertArrayEquals(stringData1.getBytes(StandardCharsets.UTF_8), EncodingTools.b64Decode(stringData1Base64)); ;
    }

    @Test
    public void testHexStringEncode()
    {
        Assert.assertEquals("", EncodingTools.hexStringEncode(null)); ;
        Assert.assertEquals("", EncodingTools.hexStringEncode("".getBytes(StandardCharsets.US_ASCII))); ;
        Assert.assertEquals(stringData0Hexa, EncodingTools.hexStringEncode(stringData0.getBytes(StandardCharsets.UTF_8))); ;
        Assert.assertEquals(stringData1Hexa, EncodingTools.hexStringEncode(stringData1.getBytes(StandardCharsets.UTF_8))); ;
    }

    @Test
    public void testHexStringDecode()
    {
        Assert.assertArrayEquals("".getBytes(StandardCharsets.US_ASCII), EncodingTools.hexStringDecode(null)); ;
        Assert.assertArrayEquals("".getBytes(StandardCharsets.US_ASCII), EncodingTools.hexStringDecode("")); ;
        Assert.assertArrayEquals(stringData0.getBytes(StandardCharsets.UTF_8), EncodingTools.hexStringDecode(stringData0Hexa)); ;
        Assert.assertArrayEquals(stringData1.getBytes(StandardCharsets.UTF_8), EncodingTools.hexStringDecode(stringData1Hexa)); ;
    }

    @Test
    public void testToSHA2()
    {
        Assert.assertEquals(stringData0HashHexa, EncodingTools.toSHA2(stringData0)); ;
        Assert.assertEquals(stringData1HashHexa, EncodingTools.toSHA2(stringData1)); ;
    }
}
