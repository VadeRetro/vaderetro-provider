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
public class DateEntry
{
    private String alias;
    private Date date;
    
    public DateEntry(String alias, Date date)
    {
        this.alias = alias;
        this.date = date;
    }

    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public Date getDate()
    {
        return date;
    }

    public void setDate(Date date)
    {
        this.date = date;
    }
    
    public static DateEntry create(String alias)
    {
        return new DateEntry(alias, Date.from(Instant.now()));
    }
}
