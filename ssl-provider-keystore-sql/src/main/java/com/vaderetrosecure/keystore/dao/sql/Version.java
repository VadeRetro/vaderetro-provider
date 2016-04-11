/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

/**
 * @author ahonore
 *
 */
class Version
{
    private String tableName;
    private int tableVersion;
    
    public Version(String tableName, int tableVersion)
    {
        this.tableName = tableName;
        this.tableVersion = tableVersion;
    }
    public String getTableName()
    {
        return tableName;
    }
    public void setTableName(String tableName)
    {
        this.tableName = tableName;
    }
    public int getTableVersion()
    {
        return tableVersion;
    }
    public void setTableVersion(int tableVersion)
    {
        this.tableVersion = tableVersion;
    }
    
}
