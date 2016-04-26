/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

/**
 * This class represents a version number associated to a table name.
 * It is used by {@code StructureManager} objects to manage table verions.
 * 
 * @see StructureManager
 */
class Version
{
    private String tableName;
    private int tableVersion;
    
    /**
     * Construct a new {@code Version} object.
     * 
     * @param tableName the name of the table.
     * @param tableVersion the version of the table.
     */
    public Version(String tableName, int tableVersion)
    {
        this.tableName = tableName;
        this.tableVersion = tableVersion;
    }
    
    /**
     * Return the name of the table from this object.
     * 
     * @return the name of the table.
     */
    public String getTableName()
    {
        return tableName;
    }
    
    /**
     * Assign the name of a table to this object.
     * 
     * @param tableName the name of a table.
     */
    public void setTableName(String tableName)
    {
        this.tableName = tableName;
    }
    
    /**
     * Give the version of the associated table.
     * 
     * @return the version number of the table.
     */
    public int getTableVersion()
    {
        return tableVersion;
    }
    
    /**
     * Assign a version number to the name of the table defined in this object.
     * 
     * @param tableVersion the version number.
     */
    public void setTableVersion(int tableVersion)
    {
        this.tableVersion = tableVersion;
    }
}
