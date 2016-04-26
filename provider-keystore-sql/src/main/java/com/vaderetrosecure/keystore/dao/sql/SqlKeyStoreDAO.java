/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.sql.DataSource;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.LockedKeyProtection;

/**
 * This class implements the DAO backed by an SQL database.
 * Please, refer to the associated factory and the package documentation to know 
 * how to use it properly.
 * 
 * @see SqlKeyStoreDAOFactory
 * @see com.vaderetrosecure.keystore.dao.sql
 */
class SqlKeyStoreDAO implements KeyStoreDAO
{
    private static final Logger LOG = Logger.getLogger(SqlKeyStoreDAO.class);
    
    private static final String SQL_DELETE_FROM = "delete from ";
    private static final String SQL_INSERT_INTO = "insert into ";
    private static final String SQL_SELECT_FROM = "select * from ";
    private static final String SQL_WHERE_ALIAS_HASH = " where alias_hash=?";

    private DataSource dataSource;
    private StructureManager structureManager;

    /**
     * Construct a new {@code SqlKeyStoreDAO} object.
     * A {@code DataSource} object is given to manage SQL connections.
     * 
     * @param dataSource the DataSource object.
     * @param structureManager an object that manages the underlying structure.
     */
    SqlKeyStoreDAO(DataSource dataSource, StructureManager structureManager)
    {
        this.dataSource = dataSource;
        this.structureManager = structureManager;
    }

    /**
     * Return the {@code DataSource} object associated to this object.
     * It is used internally by other classes of the implementation.
     * 
     * @return the {@code DataSource} object.
     */
    DataSource getDataSource()
    {
        return dataSource;
    }
    
    @Override
    public void checkDAOStructure() throws KeyStoreDAOException
    {
        if (!structureManager.versionsTableExists())
            structureManager.createVersionsTable();
        structureManager.manageIntegrityTable();
        structureManager.manageEntriesTable();
        structureManager.manageCertificateChainsTable();
        structureManager.manageNamesTable();
    }

    @Override
    public int countEntries() throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select count(alias_hash) from " + StructureManager.ENTRIES_TABLE); ResultSet rs = ps.executeQuery())
        {
            if (!rs.next())
                return 0;

            return rs.getInt(1);
        }
        catch (SQLException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public List<String> getAliases() throws KeyStoreDAOException
    {
        List<String> aliases = new ArrayList<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct alias from " + StructureManager.ENTRIES_TABLE); ResultSet rs = ps.executeQuery())
        {
            while (rs.next())
                aliases.add(rs.getString(1));

            return aliases;
        }
        catch (SQLException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public List<String> getAliases(String algorithm) throws KeyStoreDAOException
    {
        List<String> aliases = new ArrayList<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct alias from " + StructureManager.ENTRIES_TABLE + " where algorithm=?"))
        {
            ps.setString(1, algorithm);
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                    aliases.add(rs.getString(1));
            }

            return aliases;
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public IntegrityData getIntegrityData() throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement(SQL_SELECT_FROM + StructureManager.INTEGRITY_TABLE + " where id=?"); )
        {
            ps.setLong(1,  1L);
            try (ResultSet rs = ps.executeQuery())
            {
                if (rs.next())
                {
                    return new IntegrityData(
                            EncodingTools.b64Decode(rs.getString("salt")),
                            EncodingTools.b64Decode(rs.getString("iv")),
                            EncodingTools.b64Decode(rs.getString("data")),
                            EncodingTools.hexStringDecode(rs.getString("data_hash"))
                            );
                }
            }
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }

        return null;
    }

    @Override
    public void setIntegrityData(IntegrityData integrityData) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            boolean autoCom = conn.getAutoCommit();
            conn.setAutoCommit(false);

            try (PreparedStatement ps = conn.prepareStatement(SQL_DELETE_FROM + StructureManager.INTEGRITY_TABLE + " where id=?"))
            {
                ps.setLong(1, 1L);
                ps.executeUpdate();
            }
            
            try (PreparedStatement ps = conn.prepareStatement(SQL_INSERT_INTO + StructureManager.INTEGRITY_TABLE + " (id,salt,iv,data,data_hash) value(?,?,?,?,?)"))
            {
                ps.setLong(1, 1L);
                ps.setString(2, EncodingTools.b64Encode(integrityData.getSalt()));
                ps.setString(3, EncodingTools.b64Encode(integrityData.getIV()));
                ps.setString(4, EncodingTools.b64Encode(integrityData.getCipheredData()));
                ps.setString(5, EncodingTools.hexStringEncode(integrityData.getDataHash()));
                ps.executeUpdate();
            }

            conn.commit();
            conn.setAutoCommit(autoCom);
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public KeyStoreEntry getEntry(String alias) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            String aliasHash = EncodingTools.toSHA2(alias);
            KeyStoreEntry kse = getKeyStoreEntryObject(conn, aliasHash);
            if (kse != null)
            {
                kse.setCertificateChain(getCertificateChainObjectList(conn, aliasHash));
                kse.setNames(getNameObjectList(conn, aliasHash));
            }
            
            return kse;
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public List<KeyStoreEntry> getEntries(String name) throws KeyStoreDAOException
    {
        List<KeyStoreEntry> entries = new ArrayList<>();
        try (Connection conn = dataSource.getConnection())
        {
            String nameHash = EncodingTools.toSHA2(name);
            Set<String> aliasHashes = getAliasHashesFromNameHash(conn, nameHash);
            for (String aliasHash : aliasHashes)
            {
                KeyStoreEntry kse = getKeyStoreEntryObject(conn, aliasHash);
                if (kse != null)
                {
                    kse.setCertificateChain(getCertificateChainObjectList(conn, aliasHash));
                    kse.setNames(getNameObjectList(conn, aliasHash));
                    entries.add(kse);
                }
            }
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
        
        return entries;
    }

    @Override
    public void setEntry(KeyStoreEntry entry) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            boolean autoCom = conn.getAutoCommit();
            conn.setAutoCommit(false);

            String aliasHash = EncodingTools.toSHA2(entry.getAlias());
            setKeyStoreEntryObject(conn, aliasHash, entry);
            setCertificateChainObjectList(conn, aliasHash, entry.getCertificateChain());
            setNameObjectList(conn, aliasHash, entry.getNames());
            
            conn.commit();
            conn.setAutoCommit(autoCom);
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public void deleteEntry(KeyStoreEntry entry) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            boolean autoCom = conn.getAutoCommit();
            conn.setAutoCommit(false);

            String aliasHash = EncodingTools.toSHA2(entry.getAlias());
            deleteKeyStoreEntryObject(conn, aliasHash);
            deleteCertificateChainObjectList(conn, aliasHash);
            deleteNameObjectList(conn, aliasHash);
            
            conn.commit();
            conn.setAutoCommit(autoCom);
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    private KeyStoreEntry getKeyStoreEntryObject(Connection conn, String aliasHash) throws SQLException
    {
        KeyStoreEntry kse = null;
        try (PreparedStatement ps = conn.prepareStatement(SQL_SELECT_FROM + StructureManager.ENTRIES_TABLE + SQL_WHERE_ALIAS_HASH))
        {
            ps.setString(1, aliasHash);
            try (ResultSet rs = ps.executeQuery())
            {
                if (!rs.next())
                    return null;

                LockedKeyProtection lkp = null;
                String protectKey = rs.getString("protection_key");
                String protectParam = rs.getString("protection_param");
                if ((protectKey != null) && (protectParam != null))
                    lkp = new LockedKeyProtection(EncodingTools.b64Decode(protectKey), EncodingTools.b64Decode(protectParam));
                kse = new KeyStoreEntry(
                        rs.getString("alias"), 
                        Date.from(Instant.ofEpochMilli(rs.getLong("creation_date"))), 
                        KeyStoreEntryType.values()[rs.getInt("entry_type")],
                        rs.getString("algorithm"),
                        EncodingTools.b64Decode(rs.getString("data")),
                        lkp,
                        Collections.emptyList(),
                        Collections.emptyList()
                        );
            }
        }
        
        return kse;
    }

    private List<CertificateData> getCertificateChainObjectList(Connection conn, String aliasHash) throws SQLException
    {
        List<CertificateData> certChain = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(SQL_SELECT_FROM + StructureManager.CERTIFICATE_CHAINS_TABLE + SQL_WHERE_ALIAS_HASH + " order by rank"))
        {
            ps.setString(1, aliasHash);
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                {
                    certChain.add(new CertificateData(EncodingTools.b64Decode(rs.getString("data"))));
                }
            }
        }
        
        return certChain;
    }

    private List<String> getNameObjectList(Connection conn, String aliasHash) throws SQLException
    {
        List<String> names = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(SQL_SELECT_FROM + StructureManager.NAMES_TABLE + SQL_WHERE_ALIAS_HASH))
        {
            ps.setString(1, aliasHash);
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                {
                    names.add(rs.getString("name"));
                }
            }
        }
        
        return names;
    }

    private Set<String> getAliasHashesFromNameHash(Connection conn, String nameHash) throws SQLException
    {
        Set<String> aliasHashes = new HashSet<>();
        try (PreparedStatement ps = conn.prepareStatement(SQL_SELECT_FROM + StructureManager.NAMES_TABLE + " where name_hash=?"))
        {
            ps.setString(1, nameHash);
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                {
                    aliasHashes.add(rs.getString("alias_hash"));
                }
            }
        }
        
        return aliasHashes;
    }

    private void setKeyStoreEntryObject(Connection conn, String aliasHash, KeyStoreEntry kse) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement(SQL_INSERT_INTO + StructureManager.ENTRIES_TABLE + " (alias_hash,entry_type,alias,creation_date,algorithm,data,protection_key,protection_param) value(?,?,?,?,?,?,?,?)"))
        {
            ps.setString(1, aliasHash);
            ps.setInt(2, kse.getEntryType().ordinal());
            ps.setString(3, kse.getAlias());
            ps.setLong(4, kse.getCreationDate().getTime());
            ps.setString(5, kse.getAlgorithm());
            ps.setString(6, EncodingTools.b64Encode(kse.getEntryData()));
            ps.setString(7, EncodingTools.b64Encode(kse.getLockedKeyProtection().getCipheredKey()));
            ps.setString(8, EncodingTools.b64Encode(kse.getLockedKeyProtection().getIV()));
            
            ps.executeUpdate();
        }
    }

    private void setCertificateChainObjectList(Connection conn, String aliasHash, List<CertificateData> certificateChain) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement(SQL_INSERT_INTO + StructureManager.CERTIFICATE_CHAINS_TABLE + " (alias_hash,rank,data) value(?,?,?)"))
        {
            int ct = 0;
            for (CertificateData cd : certificateChain)
            {
                ps.setString(1, aliasHash);
                ps.setInt(2, ct);
                ps.setString(3, EncodingTools.b64Encode(cd.getEncodedCertificate()));
                
                ps.executeUpdate();
                ct++;
            }
        }
    }

    private void setNameObjectList(Connection conn, String aliasHash, List<String> names) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement(SQL_INSERT_INTO + StructureManager.NAMES_TABLE + " (alias_hash,name_hash,name) value(?,?,?)"))
        {
            for (String name : names)
            {
                ps.setString(1, aliasHash);
                ps.setString(2, EncodingTools.toSHA2(name));
                ps.setString(3, name);
    
                ps.executeUpdate();
            }
        }
    }

    private void deleteKeyStoreEntryObject(Connection conn, String aliasHash) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement(SQL_DELETE_FROM + StructureManager.ENTRIES_TABLE + SQL_WHERE_ALIAS_HASH))
        {
            ps.setString(1, aliasHash);
            ps.executeUpdate();
        }
    }

    private void deleteCertificateChainObjectList(Connection conn, String aliasHash) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement(SQL_DELETE_FROM + StructureManager.CERTIFICATE_CHAINS_TABLE + SQL_WHERE_ALIAS_HASH))
        {
            ps.setString(1, aliasHash);
            ps.executeUpdate();
        }
    }

    private void deleteNameObjectList(Connection conn, String aliasHash) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement(SQL_DELETE_FROM + StructureManager.NAMES_TABLE + SQL_WHERE_ALIAS_HASH))
        {
            ps.setString(1, aliasHash);
            ps.executeUpdate();
        }
    }
}
