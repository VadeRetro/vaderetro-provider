/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * @author ahonore
 *
 */
public class KeyEntry
{
    private String alias;
    private String algorithm;
    private String algorithmParameters;
    private String keyData;

    public KeyEntry()
    {
        this("", "", "", "");
    }

    public KeyEntry(String alias, String algorithm, String algorithmParameters, String keyData)
    {
        super();
        this.alias = alias;
        this.algorithm = algorithm;
        this.algorithmParameters = algorithmParameters;
        this.keyData = keyData;
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public String getAlgorithmParameters()
    {
        return algorithmParameters;
    }

    public void setAlgorithmParameters(String algorithmParameters)
    {
        this.algorithmParameters = algorithmParameters;
    }

    public String getKeyData()
    {
        return keyData;
    }

    public void setKeyData(String keyData)
    {
        this.keyData = keyData;
    }

}
