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
class KeyStoreEntry
{
    private String alias;
    private Date creationDate;

    protected KeyStoreEntry()
    {
        this("", Date.from(Instant.now()));
    }

    protected KeyStoreEntry(String alias, Date creationDate)
    {
        this.alias = alias;
        this.creationDate = creationDate;
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public Date getCreationDate()
    {
        return creationDate;
    }

    public void setCreationDate(Date creationDate)
    {
        this.creationDate = creationDate;
    }
}
