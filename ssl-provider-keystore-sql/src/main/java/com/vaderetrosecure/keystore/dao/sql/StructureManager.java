/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;

/**
 * @author ahonore
 *
 */
class StructureManager
{
    private static final Logger LOG = Logger.getLogger(StructureManager.class);

    public static final String VERSIONS_TABLE = "versions";
    public static final String ENTRIES_TABLE = "entries";
    public static final String INTEGRITY_TABLE = "integrity";
    public static final String NAMES_TABLE = "names";
    public static final String CERTIFICATE_CHAINS_TABLE = "certificate_chains";
    
    public static final int ENTRIES_VERSION = 1;
    public static final int INTEGRITY_VERSION = 1;
    public static final int NAMES_VERSION = 1;
    public static final int CERTIFICATE_CHAINS_VERSION = 1;
    
    private DataSource dataSource;
    
    public StructureManager(DataSource dataSource)
    {
        this.dataSource = dataSource;
    }
    
    public boolean versionsTableExists() throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getTables(null, null, VERSIONS_TABLE, new String[] {"TABLE"}))
            {
                if (!rs.next())
                    return false;
                
                return true;
            }
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }
    
    public void manageKeysTable() throws KeyStoreDAOException
    {
        StringBuilder sb = new StringBuilder();
        sb.append("create table if not exists ");
        sb.append(ENTRIES_TABLE);
        sb.append(" (");
        sb.append("alias_hash varchar(64) not null");sb.append(",");
        sb.append("entry_type int default 0");sb.append(",");
        sb.append("alias varchar(256) not null");sb.append(",");
        sb.append("creation_date bigint default 0");sb.append(",");
        sb.append("algorithm varchar(32)");sb.append(",");
        sb.append("data text not null");sb.append(",");
        sb.append("protection_key text");sb.append(",");
        sb.append("protection_param varchar(128)");sb.append(",");
        sb.append("primary key(alias_hash)");sb.append(",");
        sb.append("key(algorithm)");
        sb.append(")");

        try (Connection conn = dataSource.getConnection())
        {
        	if (getVersion(conn, ENTRIES_TABLE) != ENTRIES_VERSION)
        	{
	            try (PreparedStatement ps = conn.prepareStatement(sb.toString()))
	            {
	                ps.execute();
	            }
	            
	            insertVersion(conn, new Version(ENTRIES_TABLE, ENTRIES_VERSION));
        	}
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }
    
    public void manageCertificateChainsTable() throws KeyStoreDAOException
    {
        StringBuilder sb = new StringBuilder();
        sb.append("create table if not exists ");
        sb.append(CERTIFICATE_CHAINS_TABLE);
        sb.append(" (");
        sb.append("alias_hash varchar(64) not null");sb.append(",");
        sb.append("rank int default 0");sb.append(",");
        sb.append("data text not null");sb.append(",");
        sb.append("primary key (alias_hash, rank)");
        sb.append(")");

        try (Connection conn = dataSource.getConnection())
        {
        	if (getVersion(conn, CERTIFICATE_CHAINS_TABLE) != CERTIFICATE_CHAINS_VERSION)
        	{
	            try (PreparedStatement ps = conn.prepareStatement(sb.toString()))
	            {
	                ps.execute();
	            }
	            
	            insertVersion(conn, new Version(CERTIFICATE_CHAINS_TABLE, CERTIFICATE_CHAINS_VERSION));
        	}
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }
    
    public void manageNamesTable() throws KeyStoreDAOException
    {
        StringBuilder sb = new StringBuilder();
        sb.append("create table if not exists ");
        sb.append(NAMES_TABLE);
        sb.append(" (");
        sb.append("alias_hash varchar(64) not null");sb.append(",");
        sb.append("name_hash varchar(64) not null");sb.append(",");
        sb.append("name varchar(256) not null");sb.append(",");
        sb.append("primary key(alias_hash, name_hash)");sb.append(",");
        sb.append("key (name_hash)");
        sb.append(")");

        try (Connection conn = dataSource.getConnection())
        {
        	if (getVersion(conn, NAMES_TABLE) != NAMES_VERSION)
        	{
	            try (PreparedStatement ps = conn.prepareStatement(sb.toString()))
	            {
	                ps.execute();
	            }
	            
	            insertVersion(conn, new Version(NAMES_TABLE, NAMES_VERSION));
        	}
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }
    
    public void manageIntegrityTable() throws KeyStoreDAOException
    {
        StringBuilder sb = new StringBuilder();
        sb.append("create table if not exists ");
        sb.append(INTEGRITY_TABLE);
        sb.append(" (");
        sb.append("id bigint not null");sb.append(",");
        sb.append("salt varchar(128) not null");sb.append(",");
        sb.append("iv varchar(128) not null");sb.append(",");
        sb.append("data varchar(256) not null");sb.append(",");
        sb.append("data_hash varchar(64) not null");sb.append(",");
        sb.append("primary key(id)");
        sb.append(")");

        try (Connection conn = dataSource.getConnection())
        {
        	if (getVersion(conn, INTEGRITY_TABLE) != INTEGRITY_VERSION)
        	{
	            try (PreparedStatement ps = conn.prepareStatement(sb.toString()))
	            {
	                ps.execute();
	            }
	            
	            insertVersion(conn, new Version(INTEGRITY_TABLE, INTEGRITY_VERSION));
        	}
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }
    
    public void createVersionsTable() throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("create table if not exists " + VERSIONS_TABLE + " (table_name varchar(128) not null, version int not null, primary key(table_name))"))
        {
            ps.execute();
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }
    
    private int getVersion(Connection conn, String tableName) throws SQLException
    {
    	int version = 0;
    	try (PreparedStatement ps = conn.prepareStatement("select * from " + VERSIONS_TABLE + " where table_name=?"))
    	{
    		ps.setString(1, tableName);
    		try (ResultSet rs = ps.executeQuery())
    		{
    			if (rs.next())
    				version = rs.getInt("version");
    		}
    	}
    	
    	return version;
    }
    
    private void insertVersion(Connection conn, Version version) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement("insert into " + VERSIONS_TABLE + " (table_name, version) value(?,?) on duplicate key update version=?"))
        {
            ps.setString(1, version.getTableName());
            ps.setInt(2, version.getTableVersion());
            ps.setInt(3, version.getTableVersion());
            ps.executeUpdate();
        }
    }
}
