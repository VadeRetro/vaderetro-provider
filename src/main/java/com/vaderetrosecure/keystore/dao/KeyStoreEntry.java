/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @author ahonore
 *
 */
public class KeyStoreEntry
{
    private String alias;
    private KeyStoreEntryType entryType;
    private int rank;
    private Date creationDate;
    private String algorithm;
    private byte[] data;

    public KeyStoreEntry()
    {
        this("", KeyStoreEntryType.KEY, 0, Date.from(Instant.now()), "", null);
    }

    public KeyStoreEntry(String alias, KeyStoreEntryType entryType, int rank, Date creationDate, String algorithm, byte[] data)
    {
        this.alias = alias;
        this.entryType = entryType;
        this.rank = rank;
        this.creationDate = creationDate;
        this.algorithm = algorithm;
        setData(data);
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public KeyStoreEntryType getEntryType()
    {
        return entryType;
    }

    public void setEntryType(KeyStoreEntryType entryType)
    {
        this.entryType = entryType;
    }

    public int getRank()
    {
        return rank;
    }

    public void setRank(int rank)
    {
        this.rank = rank;
    }

    public Date getCreationDate()
    {
        return creationDate;
    }

    public void setCreationDate(Date creationDate)
    {
        this.creationDate = creationDate;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public byte[] getData()
    {
        return data;
    }

    public void setData(byte[] data)
    {
        this.data = data;
    }
}
