/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.time.Instant;
import java.util.Date;

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
    private byte[] data;

    public KeyStoreEntry()
    {
        this("", KeyStoreEntryType.KEY, 0, Date.from(Instant.now()), null);
    }

    public KeyStoreEntry(String alias, KeyStoreEntryType entryType, int rank, Date creationDate, byte[] data)
    {
        this.alias = alias;
        this.entryType = entryType;
        this.rank = rank;
        this.creationDate = creationDate;
        this.data = data;
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

    public byte[] getData()
    {
        return data;
    }

    public void setData(byte[] data)
    {
        this.data = data;
    }
    
}
