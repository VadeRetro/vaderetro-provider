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
import java.util.List;

import javax.sql.DataSource;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;

/**
 * @author ahonore
 *
 */
class SqlKeyStoreDAO implements KeyStoreDAO
{
    private static final Logger LOG = Logger.getLogger(SqlKeyStoreDAO.class);

    private DataSource dataSource;

    SqlKeyStoreDAO(DataSource dataSource)
    {
        this.dataSource = dataSource;
    }

    @Override
    public void checkDAOStructure() throws KeyStoreDAOException
    {
        StructureManager sm = new StructureManager(dataSource);
        if (sm.versionsTableExists())
            return;
        
        sm.createVersionsTable();
        sm.manageIntegrityTable();
        sm.manageKeysTable();
        sm.manageCertificateChainsTable();
        sm.manageNamesTable();
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
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select * from " + StructureManager.INTEGRITY_TABLE + " where id=?"); )
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

            try (PreparedStatement ps = conn.prepareStatement("delete from " + StructureManager.INTEGRITY_TABLE + " where id=?"))
            {
                ps.setLong(1, 1L);
                ps.executeUpdate();
            }
            
            try (PreparedStatement ps = conn.prepareStatement("insert into " + StructureManager.INTEGRITY_TABLE + " (id,salt,iv,data,data_hash) value(?,?,?,?,?)"))
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
            
            try (PreparedStatement ps = conn.prepareStatement("select * from " + StructureManager.ENTRIES_TABLE + " where alias_hash=?"))
            {
                ps.setString(1, 1L);
                ps.executeUpdate();
            }
            
            try (PreparedStatement ps = conn.prepareStatement("insert into " + StructureManager.INTEGRITY_TABLE + " (id,salt,iv,data,data_hash) value(?,?,?,?,?)"))
            {
                ps.setLong(1, 1L);
                ps.setString(2, EncodingTools.b64Encode(integrityData.getSalt()));
                ps.setString(3, EncodingTools.b64Encode(integrityData.getIV()));
                ps.setString(4, EncodingTools.b64Encode(integrityData.getCipheredData()));
                ps.setString(5, EncodingTools.hexStringEncode(integrityData.getDataHash()));
                ps.executeUpdate();
            }
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
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void setEntry(KeyStoreEntry entry) throws KeyStoreDAOException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void deleteEntry(KeyStoreEntry entry) throws KeyStoreDAOException
    {
        // TODO Auto-generated method stub
        
    }

    private KeyStoreEntry getKeyStoreEntryObject(Connection conn, String aliasHash) throws SQLException
    {
        KeyStoreEntry kse = null;
        try (PreparedStatement ps = conn.prepareStatement("select * from " + StructureManager.ENTRIES_TABLE + " where alias_hash=?"))
        {
            ps.setString(1, aliasHash);
            try (ResultSet rs = ps.executeQuery())
            {
                if (rs.next())
                {
                    kse = new KeyStoreEntry(
                            rs.getString("alias"), 
                            Date.from(Instant.ofEpochMilli(rs.getLong("creation_date"))), 
                            KeyStoreEntryType.values()[rs.getInt("entry_type")],
                            rs.getString("algorithm"),
                                );
                }
            }
        }
        
        return kse;
    }

    private List<CertificateData> getCertificateChainObjectList(Connection conn, String aliasHash)
    {
        return new ArrayList<>();
    }

    private List<String> getNameObjectList(Connection conn, String aliasHash)
    {
        return new ArrayList<>();
    }
    
//    @Override
//    public int countEntries() throws KeyStoreDAOException
//    {
//        int count = 0;
//        try (Connection conn = dataSource.getConnection())
//        {
//            try (PreparedStatement ps = conn.prepareStatement("select distinct count(alias_hash) from " + StructureManager.KEYS_TABLE); ResultSet rs = ps.executeQuery())
//            {
//                if (!rs.next())
//                    return 0;
//    
//                count += rs.getInt(1);
//            }
//
//            try (PreparedStatement ps = conn.prepareStatement("select distinct count(alias_hash) from " + StructureManager.CERTIFICATES_TABLE); ResultSet rs = ps.executeQuery())
//            {
//                if (!rs.next())
//                    return 0;
//    
//                count += rs.getInt(1);
//            }
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//        
//        return count;
//    }
//
//    @Override
//    public List<String> getAliases() throws KeyStoreDAOException
//    {
//        Set<String> aliases = new HashSet<>();
//        try (Connection conn = dataSource.getConnection())
//        {
//            try (PreparedStatement ps = conn.prepareStatement("select distinct alias_hash, alias from " + StructureManager.KEYS_TABLE); ResultSet rs = ps.executeQuery())
//            {
//                while (rs.next())
//                    aliases.add(rs.getString("alias"));
//            }
//
//            try (PreparedStatement ps = conn.prepareStatement("select distinct alias_hash, alias from " + StructureManager.CERTIFICATES_TABLE); ResultSet rs = ps.executeQuery())
//            {
//                while (rs.next())
//                    aliases.add(rs.getString("alias"));
//            }
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//
//        return new ArrayList<>(aliases);
//    }
//
//    @Override
//    public List<String> getAuthenticationAliases(String keyType) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public IntegrityData getIntegrityData() throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public void setIntegrityData(IntegrityData integrityData) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        
//    }
//
//    @Override
//    public KeyEntry getKeyEntry(String alias) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public void setEntry(KeyEntry keyEntry) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        
//    }
//
//    @Override
//    public void deleteKeyEntry(String alias) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        
//    }
//
//    @Override
//    public CertificatesEntry getCertificatesEntry(String alias) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public List<CertificatesEntry> getCertificatesEntries(String name) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public void setEntry(CertificatesEntry certificatesEntry) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        
//    }
//
//    @Override
//    public void deleteCertificatesEntry(String alias) throws KeyStoreDAOException
//    {
//        // TODO Auto-generated method stub
//        
//    }

//    @Override
//    public void createSchema() throws KeyStoreDAOException
//    {
//        try (Connection conn = dataSource.getConnection())
//        {
//            boolean autoCom = conn.getAutoCommit();
//            conn.setAutoCommit(false);
//            try (BufferedReader br = new BufferedReader(new InputStreamReader(getClass().getClassLoader().getResourceAsStream("schema.sql"))))
//            {
//                String line;
//                while ((line = br.readLine()) != null)
//                {
//                    line = line.trim();
//                    if (line.isEmpty())
//                        continue;
//
//                    try (PreparedStatement ps = conn.prepareStatement(line))
//                    {
//                        ps.executeUpdate();
//                    }
//                }
//            }
//
//            conn.commit();
//            conn.setAutoCommit(autoCom);
//        }
//        catch (SQLException e)
//        {
//            LOG.error(e, e);
//            throw new KeyStoreDAOException(e);
//        }
//        catch (IOException e)
//        {
//            LOG.error(e, e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public KeyStoreMetaData getMetaData() throws KeyStoreDAOException
//    {
//        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_METADATA_TABLE + " limit 1"); ResultSet rs = ps.executeQuery())
//        {
//            if (!rs.next())
//                return null;
//
//            KeyStoreMetaData ksmd = new KeyStoreMetaData();
//            ksmd.setMajorVersion(rs.getInt("major_version"));
//            ksmd.setVersion(rs.getString("version"));
//            ksmd.setSalt(EncodingTools.b64Decode(rs.getString("salt")));
//            ksmd.setIV(EncodingTools.b64Decode(rs.getString("iv")));
//            ksmd.setKeyIV(EncodingTools.b64Decode(rs.getString("key_iv")));
//            ksmd.setKeyIVHash(EncodingTools.hexStringDecode(rs.getString("key_iv_hash")));
//            return ksmd;
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public int countEntries() throws KeyStoreDAOException
//    {
//        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct count(alias_hash) from " + KEYSTORE_ENTRIES_TABLE); ResultSet rs = ps.executeQuery())
//        {
//            if (!rs.next())
//                return 0;
//
//            return rs.getInt(1);
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public List<String> getAliases() throws KeyStoreDAOException
//    {
//        List<String> aliases = new ArrayList<>();
//        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct alias from " + KEYSTORE_ENTRIES_TABLE); ResultSet rs = ps.executeQuery())
//        {
//            while (rs.next())
//                aliases.add(rs.getString(1));
//
//            return aliases;
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//    
//    @Override
//    public List<String> getAuthenticationAliases(String keyType) throws KeyStoreDAOException
//    {
//        Set<String> aliases = new HashSet<>();
//        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct alias from " + KEYSTORE_ENTRIES_TABLE + " where entry_type=? and rank=? and algorithm=?"))
//        {
//            ps.setInt(1, KeyStoreEntryType.PRIVATE_KEY.ordinal());
//            ps.setInt(2, 0);
//            ps.setString(3, keyType);
//            try (ResultSet rs = ps.executeQuery())
//            {
//                while (rs.next())
//                    aliases.add(rs.getString(1));
//            }
//
//            Set<String> certAliases = new HashSet<>();
//            ps.setInt(1, KeyStoreEntryType.CERTIFICATE.ordinal());
//            ps.setInt(2, 0);
//            ps.setString(3, keyType);
//            try (ResultSet rs = ps.executeQuery())
//            {
//                while (rs.next())
//                    certAliases.add(rs.getString(1));
//            }
//
//            aliases.retainAll(certAliases);
//            return new ArrayList<>(aliases);
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public List<KeyStoreEntry> getKeyStoreEntry(String alias, KeyStoreEntryType keyStoreEntryType) throws KeyStoreDAOException
//    {
//        List<KeyStoreEntry> entries = new ArrayList<>();
//        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=? and entry_type=?"))
//        {
//            ps.setString(1, EncodingTools.toSHA2(alias));
//            ps.setInt(2, keyStoreEntryType.ordinal());
//            try (ResultSet rs = ps.executeQuery())
//            {
//                while (rs.next())
//                    entries.add(getKeyStoreEntryObject(rs));
//            }
//            return entries;
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public List<KeyStoreEntry> getKeyStoreEntry(String alias) throws KeyStoreDAOException
//    {
//        List<KeyStoreEntry> entries = new ArrayList<>();
//        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=?"))
//        {
//            ps.setString(1, EncodingTools.toSHA2(alias));
//            try (ResultSet rs = ps.executeQuery())
//            {
//                while (rs.next())
//                    entries.add(getKeyStoreEntryObject(rs));
//            }
//            return entries;
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public Date engineGetCreationDate(String alias) throws KeyStoreDAOException
//    {
//        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select creation_date from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=? limit 1"))
//        {
//            ps.setString(1, EncodingTools.toSHA2(alias));
//            try (ResultSet rs = ps.executeQuery())
//            {
//                if (rs.next())
//                {
//                    return Date.from(Instant.ofEpochMilli(rs.getLong(1)));
//                }
//            }
//            return null;
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public List<KeyStoreEntry> getKeyStoreEntriesByName(String name) throws KeyStoreDAOException
//    {
//        try (Connection conn = dataSource.getConnection())
//        {
//            List<String> aliasHashes = new ArrayList<>();
//            try (PreparedStatement ps = conn.prepareStatement("select alias_hash from " + KEYSTORE_NAMES_TABLE + " where name_hash=? and rank=?"))
//            {
//                ps.setString(1, EncodingTools.toSHA2(name));
//                ps.setInt(2, 0);
//                try (ResultSet rs = ps.executeQuery())
//                {
//                    while (rs.next())
//                    {
//                        aliasHashes.add(rs.getString(1));
//                    }
//                }
//            }
//            
//            List<KeyStoreEntry> entries = new ArrayList<>();
//            try (PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=? and entry_type=? and rank=?"))
//            {
//                for (String aliasHash : aliasHashes)
//                {
//                    ps.setString(1, aliasHash);
//                    ps.setInt(2, KeyStoreEntryType.CERTIFICATE.ordinal());
//                    ps.setInt(3, 0);
//                    try (ResultSet rs = ps.executeQuery())
//                    {
//                        while (rs.next())
//                        {
//                            entries.add(getKeyStoreEntryObject(rs));
//                        }
//                    }
//                }
//            }
//            
//            return entries;
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//    
//    @Override
//    public void setMetaData(KeyStoreMetaData keyStoreMetaData) throws KeyStoreDAOException
//    {
//        // delete if exists then insert
//        try (Connection conn = dataSource.getConnection())
//        {
//            boolean autoCom = conn.getAutoCommit();
//            conn.setAutoCommit(false);
//
//            try (PreparedStatement ps = conn.prepareStatement("delete from " + KEYSTORE_METADATA_TABLE + " where major_version=?"))
//            {
//                ps.setInt(1, keyStoreMetaData.getMajorVersion());
//                ps.executeUpdate();
//            }
//
//            try (PreparedStatement ps = conn.prepareStatement("insert into " + KEYSTORE_METADATA_TABLE + " (major_version,version,salt,iv,key_iv,key_iv_hash) value(?,?,?,?,?,?)"))
//            {
//                ps.setInt(1, keyStoreMetaData.getMajorVersion());
//                ps.setString(2, keyStoreMetaData.getVersion());
//                ps.setString(3, EncodingTools.b64Encode(keyStoreMetaData.getSalt()));
//                ps.setString(4, EncodingTools.b64Encode(keyStoreMetaData.getIV()));
//                ps.setString(5, EncodingTools.b64Encode(keyStoreMetaData.getKeyIV()));
//                ps.setString(6, EncodingTools.hexStringEncode(keyStoreMetaData.getKeyIVHash()));
//                ps.executeUpdate();
//            }
//
//            conn.commit();
//            conn.setAutoCommit(autoCom);
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public void setKeyStoreEntries(Collection<KeyStoreEntry> keyStoreEntries) throws KeyStoreDAOException
//    {
//        try (Connection conn = dataSource.getConnection())
//        {
//            boolean autoCom = conn.getAutoCommit();
//            conn.setAutoCommit(false);
//
//            for (String alias : getAliasesFromKeyStoreEntries(keyStoreEntries))
//            {
//                deleteKeyStoreEntries(conn, alias);
//                deleteCertificateNames(conn, alias);
//            }
//            
//            try (PreparedStatement ps = conn.prepareStatement("insert into " + KEYSTORE_ENTRIES_TABLE + " (alias_hash,alias,entry_type,rank,creation_date,algorithm,data) value(?,?,?,?,?,?,?)"))
//            {
//                for (KeyStoreEntry kse : keyStoreEntries)
//                {
//                    ps.setString(1, EncodingTools.toSHA2(kse.getAlias()));
//                    ps.setString(2, kse.getAlias());
//                    ps.setInt(3, kse.getEntryType().ordinal());
//                    ps.setInt(4, kse.getRank());
//                    ps.setLong(5, kse.getCreationDate().getTime());
//                    ps.setString(6, kse.getAlgorithm());
//                    ps.setString(7, EncodingTools.b64Encode(kse.getData()));
//                    ps.executeUpdate();
//                }
//            }
//
//            try (PreparedStatement ps = conn.prepareStatement("insert into " + KEYSTORE_NAMES_TABLE + " (alias_hash,rank,name_hash,name) value(?,?,?,?)"))
//            {
//                for (KeyStoreEntry kse : keyStoreEntries)
//                {
//                    for (String certName : kse.getNames())
//                    {
//                        ps.setString(1, EncodingTools.toSHA2(kse.getAlias()));
//                        ps.setInt(2, kse.getRank());
//                        ps.setString(3, EncodingTools.toSHA2(certName));
//                        ps.setString(4, certName);
//                        ps.executeUpdate();
//                    }
//                }
//            }
//
//            conn.commit();
//            conn.setAutoCommit(autoCom);
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    @Override
//    public void deleteEntries(Collection<String> aliases) throws KeyStoreDAOException
//    {
//        try (Connection conn = dataSource.getConnection())
//        {
//            boolean autoCom = conn.getAutoCommit();
//            conn.setAutoCommit(false);
//
//            for (String alias : aliases)
//            {
//                deleteKeyStoreEntries(conn, alias);
//                deleteCertificateNames(conn, alias);
//            }
//
//            conn.commit();
//            conn.setAutoCommit(autoCom);
//        }
//        catch (SQLException e)
//        {
//            LOG.debug(e, e);
//            LOG.error(e);
//            throw new KeyStoreDAOException(e);
//        }
//    }
//
//    private void deleteKeyStoreEntries(Connection conn, String alias) throws SQLException
//    {
//        try (PreparedStatement ps = conn.prepareStatement("delete from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=?"))
//        {
//            ps.setString(1, EncodingTools.toSHA2(alias));
//            ps.executeUpdate();
//        }
//    }
//
//    private void deleteCertificateNames(Connection conn, String alias) throws SQLException
//    {
//        try (PreparedStatement ps = conn.prepareStatement("delete from " + KEYSTORE_NAMES_TABLE + " where alias_hash=?"))
//        {
//            ps.setString(1, EncodingTools.toSHA2(alias));
//            ps.executeUpdate();
//        }
//    }
//
//    private Set<String> getAliasesFromKeyStoreEntries(Collection<KeyStoreEntry> entries)
//    {
//        Set<String> aliases = new HashSet<>();
//        for (KeyStoreEntry kse : entries)
//            aliases.add(kse.getAlias());
//        return aliases;
//    }
//    
//    private KeyStoreEntry getKeyStoreEntryObject(ResultSet resultSet) throws SQLException
//    {
//        KeyStoreEntry kse = new KeyStoreEntry();
//        kse.setAlias(resultSet.getString("alias"));
//        kse.setEntryType(KeyStoreEntryType.values()[resultSet.getInt("entry_type")]);
//        kse.setRank(resultSet.getInt("rank"));
//        kse.setCreationDate(Date.from(Instant.ofEpochMilli(resultSet.getLong("creation_date"))));
//        kse.setAlgorithm(resultSet.getString("algorithm"));
//        kse.setData(EncodingTools.b64Decode(resultSet.getString("data")));
//        return kse;
//    }
}
