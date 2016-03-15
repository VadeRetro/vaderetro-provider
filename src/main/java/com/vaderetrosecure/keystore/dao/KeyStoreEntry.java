/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * @author ahonore
 *
 */
public class KeyStoreEntry
{
    private String alias;
    private KeyStoreEntryType entryType;
    private int rank;
    private byte[] data;

    public KeyStoreEntry()
    {
        this("", KeyStoreEntryType.KEY, 0, null);
    }

    public KeyStoreEntry(String alias, KeyStoreEntryType entryType, int rank, byte[] data)
    {
        this.alias = alias;
        this.entryType = entryType;
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

    public byte[] getData()
    {
        return data;
    }

    public void setData(byte[] data)
    {
        this.data = data;
    }
    
}
