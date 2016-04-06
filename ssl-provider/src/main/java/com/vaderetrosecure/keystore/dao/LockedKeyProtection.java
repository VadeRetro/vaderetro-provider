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
    private byte[] cipheredKey;
    private byte[] iv;
    
    public LockedKeyProtection()
    {
        this(new byte[]{}, new byte[]{});
    }
    
    public LockedKeyProtection(byte[] cipheredKey, byte[] iv)
    {
        this.cipheredKey = cipheredKey;
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

    public byte[] getIV()
    {
        return iv;
    }

    public void setIV(byte[] iv)
    {
        this.iv = iv;
    }
}
