/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import org.apache.log4j.Logger;

/**
 * @author ahonore
 *
 */
public class LockedKeyProtection
{
    private final static Logger LOG = Logger.getLogger(LockedKeyProtection.class);

    private String alias;
    private byte[] iv;
    private byte[] cipheredKey;
    
    public LockedKeyProtection()
    {
        this("", new byte[]{}, new byte[]{});
    }
    
    public LockedKeyProtection(String alias, byte[] iv, byte[] cipheredKey)
    {
        this.alias = alias;
        this.iv = iv;
        this.cipheredKey = cipheredKey;
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
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

    public void setCipheredKey(byte[] cipheredKeyProtection)
    {
        this.cipheredKey = cipheredKeyProtection;
    }
}
