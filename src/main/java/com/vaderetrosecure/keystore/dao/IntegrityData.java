/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import javax.crypto.Cipher;

/**
 * @author ahonore
 *
 */
public class IntegrityData
{
    private String salt;
    private String iv;
    private String defaultPassword;
    private String defaultPasswordHash;
    
    public IntegrityData()
    {
        this("", "", "", "");
    }

    public IntegrityData(String salt, String iv, String defaultPassword, String defaultPasswordHash)
    {
        this.salt = salt;
        this.iv = iv;
        this.defaultPassword = defaultPassword;
        this.defaultPasswordHash = defaultPasswordHash;
    }

    public String getSalt()
    {
        return salt;
    }

    public void setSalt(String salt)
    {
        this.salt = salt;
    }

    public String getIv()
    {
        return iv;
    }

    public void setIv(String iv)
    {
        this.iv = iv;
    }

    public String getDefaultPassword()
    {
        return defaultPassword;
    }

    public void setDefaultPassword(String defaultPassword)
    {
        this.defaultPassword = defaultPassword;
    }

    public String getDefaultPasswordHash()
    {
        return defaultPasswordHash;
    }

    public void setDefaultPasswordHash(String defaultPasswordHash)
    {
        this.defaultPasswordHash = defaultPasswordHash;
    }
    
    public void checkIntegrity()
    {
        
    }
    
    public Cipher getCipherer()
    {
        return null;
    }
    
    public Cipher getDecipherer()
    {
        return null;
    }
}
