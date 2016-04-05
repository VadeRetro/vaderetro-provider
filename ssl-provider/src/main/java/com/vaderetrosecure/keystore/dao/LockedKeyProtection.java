/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * @author ahonore
 *
 */
public class LockedKeyProtection
{
    private byte[] iv;
    private byte[] cipheredKey;
    
    public LockedKeyProtection()
    {
        this(new byte[]{}, new byte[]{});
    }
    
    public LockedKeyProtection(byte[] iv, byte[] cipheredKey)
    {
        this.iv = iv;
        this.cipheredKey = cipheredKey;
    }

    public byte[] getIV()
    {
        return iv;
    }

    public void setIV(byte[] iv)
    {
        this.iv = iv;
    }

    public byte[] getCipheredKey()
    {
        return cipheredKey;
    }

    public void setCipheredKey(byte[] cipheredKey)
    {
        this.cipheredKey = cipheredKey;
    }
}
