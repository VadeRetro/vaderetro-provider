/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * @author ahonore
 *
 */
public class Version
{
    private static final int KEYSTORE_MAJOR_VERSION = 1;
    private static final String KEYSTORE_VERSION = "1.0.0";

    private int majorVersion;
    private String version;

    public Version()
    {
        this(0, "0.0.0");
    }
    
    public Version(int majorVersion, String version)
    {
        this.majorVersion = majorVersion;
        this.version = version;
    }

    public int getMajorVersion()
    {
        return majorVersion;
    }

    public void setMajorVersion(int majorVersion)
    {
        this.majorVersion = majorVersion;
    }

    public String getVersion()
    {
        return version;
    }

    public void setVersion(String version)
    {
        this.version = version;
    }
    
    public static Version getCurrentVersion()
    {
        return new Version(KEYSTORE_MAJOR_VERSION, KEYSTORE_VERSION);
    }
}
