/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * @author ahonore
 *
 */
public class CertificateName
{
    private String alias;
    private int rank;
    private String name;

    public CertificateName()
    {
        this("", 0, "");
    }

    public CertificateName(String alias, int rank, String name)
    {
        this.alias = alias;
        this.rank = rank;
        this.name = name;
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public int getRank()
    {
        return rank;
    }

    public void setRank(int rank)
    {
        this.rank = rank;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }
}
