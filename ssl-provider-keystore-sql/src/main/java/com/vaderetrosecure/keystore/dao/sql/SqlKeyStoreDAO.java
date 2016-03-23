/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.sql.DataSource;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;

/**
 * @author ahonore
 *
 */
class SqlKeyStoreDAO implements KeyStoreDAO
{
    private static final Logger LOG = Logger.getLogger(SqlKeyStoreDAO.class);
    private static final String KEYSTORE_ENTRIES_TABLE = "keystore_entries";
    private static final String KEYSTORE_METADATA_TABLE = "keystore_metadata";
    private static final String KEYSTORE_NAMES_TABLE = "keystore_names";

    private DataSource dataSource;

    SqlKeyStoreDAO(DataSource dataSource)
    {
        this.dataSource = dataSource;
    }

    @Override
    public void createSchema() throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            boolean autoCom = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try (BufferedReader br = new BufferedReader(new InputStreamReader(getClass().getClassLoader().getResourceAsStream("schema.sql"))))
            {
                String line;
                while ((line = br.readLine()) != null)
                {
                    line = line.trim();
                    if (line.isEmpty())
                        continue;

                    try (PreparedStatement ps = conn.prepareStatement(line))
                    {
                        ps.executeUpdate();
                    }
                }
            }

            conn.commit();
            conn.setAutoCommit(autoCom);
        }
        catch (SQLException e)
        {
            LOG.error(e, e);
            throw new KeyStoreDAOException(e);
        }
        catch (IOException e)
        {
            LOG.error(e, e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public KeyStoreMetaData getMetaData() throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_METADATA_TABLE + " limit 1"); ResultSet rs = ps.executeQuery())
        {
            if (!rs.next())
                return null;

            KeyStoreMetaData ksmd = new KeyStoreMetaData();
            ksmd.setMajorVersion(rs.getInt("major_version"));
            ksmd.setVersion(rs.getString("version"));
            ksmd.setSalt(EncodingTools.b64Decode(rs.getString("salt")));
            ksmd.setIV(EncodingTools.b64Decode(rs.getString("iv")));
            ksmd.setKeyIV(EncodingTools.b64Decode(rs.getString("key_iv")));
            ksmd.setKeyIVHash(EncodingTools.hexStringDecode(rs.getString("key_iv_hash")));
            return ksmd;
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public int countEntries() throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct count(alias_hash) from " + KEYSTORE_ENTRIES_TABLE); ResultSet rs = ps.executeQuery())
        {
            if (!rs.next())
                return 0;

            return rs.getInt(1);
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public List<String> getAliases() throws KeyStoreDAOException
    {
        List<String> aliases = new ArrayList<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct alias from " + KEYSTORE_ENTRIES_TABLE); ResultSet rs = ps.executeQuery())
        {
            while (rs.next())
                aliases.add(rs.getString(1));

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
    public List<String> getAuthenticationAliases(String keyType) throws KeyStoreDAOException
    {
        Set<String> aliases = new HashSet<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select distinct alias from " + KEYSTORE_ENTRIES_TABLE + " where entry_type=? and rank=? and algorithm=?"))
        {
            ps.setInt(1, KeyStoreEntryType.PRIVATE_KEY.ordinal());
            ps.setInt(2, 0);
            ps.setString(3, keyType);
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                    aliases.add(rs.getString(1));
            }

            Set<String> certAliases = new HashSet<>();
            ps.setInt(1, KeyStoreEntryType.CERTIFICATE.ordinal());
            ps.setInt(2, 0);
            ps.setString(3, keyType);
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                    certAliases.add(rs.getString(1));
            }

            aliases.retainAll(certAliases);
            return new ArrayList<>(aliases);
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public List<KeyStoreEntry> getKeyStoreEntry(String alias, KeyStoreEntryType keyStoreEntryType) throws KeyStoreDAOException
    {
        List<KeyStoreEntry> entries = new ArrayList<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=? and entry_type=?"))
        {
            ps.setString(1, EncodingTools.toSHA2(alias));
            ps.setInt(2, keyStoreEntryType.ordinal());
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                    entries.add(getKeyStoreEntryObject(rs));
            }
            return entries;
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public List<KeyStoreEntry> getKeyStoreEntry(String alias) throws KeyStoreDAOException
    {
        List<KeyStoreEntry> entries = new ArrayList<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=?"))
        {
            ps.setString(1, EncodingTools.toSHA2(alias));
            try (ResultSet rs = ps.executeQuery())
            {
                while (rs.next())
                    entries.add(getKeyStoreEntryObject(rs));
            }
            return entries;
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement("select creation_date from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=? limit 1"))
        {
            ps.setString(1, EncodingTools.toSHA2(alias));
            try (ResultSet rs = ps.executeQuery())
            {
                if (rs.next())
                {
                    return Date.from(Instant.ofEpochMilli(rs.getLong(1)));
                }
            }
            return null;
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public List<KeyStoreEntry> getKeyStoreEntriesByName(String name) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            List<String> aliasHashes = new ArrayList<>();
            try (PreparedStatement ps = conn.prepareStatement("select alias_hash from " + KEYSTORE_NAMES_TABLE + " where name_hash=? and rank=?"))
            {
                ps.setString(1, EncodingTools.toSHA2(name));
                ps.setInt(2, 0);
                try (ResultSet rs = ps.executeQuery())
                {
                    while (rs.next())
                    {
                        aliasHashes.add(rs.getString(1));
                    }
                }
            }
            
            List<KeyStoreEntry> entries = new ArrayList<>();
            try (PreparedStatement ps = conn.prepareStatement("select * from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=? and entry_type=? and rank=?"))
            {
                for (String aliasHash : aliasHashes)
                {
                    ps.setString(1, aliasHash);
                    ps.setInt(2, KeyStoreEntryType.CERTIFICATE.ordinal());
                    ps.setInt(3, 0);
                    try (ResultSet rs = ps.executeQuery())
                    {
                        while (rs.next())
                        {
                            entries.add(getKeyStoreEntryObject(rs));
                        }
                    }
                }
            }
            
            return entries;
        }
        catch (SQLException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new KeyStoreDAOException(e);
        }
    }
    
    @Override
    public void setMetaData(KeyStoreMetaData keyStoreMetaData) throws KeyStoreDAOException
    {
        // delete if exists then insert
        try (Connection conn = dataSource.getConnection())
        {
            boolean autoCom = conn.getAutoCommit();
            conn.setAutoCommit(false);

            try (PreparedStatement ps = conn.prepareStatement("delete from " + KEYSTORE_METADATA_TABLE + " where major_version=?"))
            {
                ps.setInt(1, keyStoreMetaData.getMajorVersion());
                ps.executeUpdate();
            }

            try (PreparedStatement ps = conn.prepareStatement("insert into " + KEYSTORE_METADATA_TABLE + " (major_version,version,salt,iv,key_iv,key_iv_hash) value(?,?,?,?,?,?)"))
            {
                ps.setInt(1, keyStoreMetaData.getMajorVersion());
                ps.setString(2, keyStoreMetaData.getVersion());
                ps.setString(3, EncodingTools.b64Encode(keyStoreMetaData.getSalt()));
                ps.setString(4, EncodingTools.b64Encode(keyStoreMetaData.getIV()));
                ps.setString(5, EncodingTools.b64Encode(keyStoreMetaData.getKeyIV()));
                ps.setString(6, EncodingTools.hexStringEncode(keyStoreMetaData.getKeyIVHash()));
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
    public void setKeyStoreEntries(Collection<KeyStoreEntry> keyStoreEntries) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            boolean autoCom = conn.getAutoCommit();
            conn.setAutoCommit(false);

            for (String alias : getAliasesFromKeyStoreEntries(keyStoreEntries))
            {
                deleteKeyStoreEntries(conn, alias);
                deleteCertificateNames(conn, alias);
            }
            
            try (PreparedStatement ps = conn.prepareStatement("insert into " + KEYSTORE_ENTRIES_TABLE + " (alias_hash,alias,entry_type,rank,creation_date,algorithm,data) value(?,?,?,?,?,?,?)"))
            {
                for (KeyStoreEntry kse : keyStoreEntries)
                {
                    ps.setString(1, EncodingTools.toSHA2(kse.getAlias()));
                    ps.setString(2, kse.getAlias());
                    ps.setInt(3, kse.getEntryType().ordinal());
                    ps.setInt(4, kse.getRank());
                    ps.setLong(5, kse.getCreationDate().getTime());
                    ps.setString(6, kse.getAlgorithm());
                    ps.setString(7, EncodingTools.b64Encode(kse.getData()));
                    ps.executeUpdate();
                }
            }

            try (PreparedStatement ps = conn.prepareStatement("insert into " + KEYSTORE_NAMES_TABLE + " (alias_hash,rank,name_hash,name) value(?,?,?,?)"))
            {
                for (KeyStoreEntry kse : keyStoreEntries)
                {
                    for (String certName : kse.getNames())
                    {
                        ps.setString(1, EncodingTools.toSHA2(kse.getAlias()));
                        ps.setInt(2, kse.getRank());
                        ps.setString(3, EncodingTools.toSHA2(certName));
                        ps.setString(4, certName);
                        ps.executeUpdate();
                    }
                }
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
    public void deleteEntries(Collection<String> aliases) throws KeyStoreDAOException
    {
        try (Connection conn = dataSource.getConnection())
        {
            boolean autoCom = conn.getAutoCommit();
            conn.setAutoCommit(false);

            for (String alias : aliases)
            {
                deleteKeyStoreEntries(conn, alias);
                deleteCertificateNames(conn, alias);
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

    private void deleteKeyStoreEntries(Connection conn, String alias) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement("delete from " + KEYSTORE_ENTRIES_TABLE + " where alias_hash=?"))
        {
            ps.setString(1, EncodingTools.toSHA2(alias));
            ps.executeUpdate();
        }
    }

    private void deleteCertificateNames(Connection conn, String alias) throws SQLException
    {
        try (PreparedStatement ps = conn.prepareStatement("delete from " + KEYSTORE_NAMES_TABLE + " where alias_hash=?"))
        {
            ps.setString(1, EncodingTools.toSHA2(alias));
            ps.executeUpdate();
        }
    }

    private Set<String> getAliasesFromKeyStoreEntries(Collection<KeyStoreEntry> entries)
    {
        Set<String> aliases = new HashSet<>();
        for (KeyStoreEntry kse : entries)
            aliases.add(kse.getAlias());
        return aliases;
    }
    
    private KeyStoreEntry getKeyStoreEntryObject(ResultSet resultSet) throws SQLException
    {
        KeyStoreEntry kse = new KeyStoreEntry();
        kse.setAlias(resultSet.getString("alias"));
        kse.setEntryType(KeyStoreEntryType.values()[resultSet.getInt("entry_type")]);
        kse.setRank(resultSet.getInt("rank"));
        kse.setCreationDate(Date.from(Instant.ofEpochMilli(resultSet.getLong("creation_date"))));
        kse.setAlgorithm(resultSet.getString("algorithm"));
        kse.setData(EncodingTools.b64Decode(resultSet.getString("data")));
        return kse;
    }
}
