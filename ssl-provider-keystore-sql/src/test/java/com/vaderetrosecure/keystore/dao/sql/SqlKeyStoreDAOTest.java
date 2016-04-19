/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.UnrecoverableKeyException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;


/**
 * @author ahonore
 *
 */
public class SqlKeyStoreDAOTest
{
    private static final String MASTER_PASSWORD = "master-password";

    private static SqlKeyStoreDAOFactory daoFactory;
    private static SecretKey secretKey;
    private KeyStoreDAO sqldao;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        secretKey = new SecretKeySpec("secret key".getBytes(StandardCharsets.US_ASCII), "AES");
        daoFactory = new TestSqlKeyStoreDAOFactory();
        daoFactory.init();
    }
    
    @Before
    public void setUp() throws Exception
    {
        sqldao = daoFactory.getKeyStoreDAO();
        dropTables(((SqlKeyStoreDAO) sqldao).getDataSource());
    }

    private void dropTables(DataSource dataSource)
    {
        try (Connection conn = dataSource.getConnection())
        {
            DatabaseMetaData meta = conn.getMetaData();
            try (ResultSet rs = meta.getTables(null, null, null, new String[] {"TABLE"}))
            {
                while (rs.next())
                {
                	try (PreparedStatement ps = conn.prepareStatement("drop table " + rs.getString(3)))
                	{
                		ps.executeUpdate();
                	}
                }
            }
        }
        catch (SQLException e)
        {
        }
    }
    
    @Test
    public void testCreateSchema() throws KeyStoreDAOException
    {
        sqldao.checkDAOStructure();
    }

    @Test
    public void testStoreLoadIntegrityData() throws KeyStoreDAOException, UnrecoverableKeyException, GeneralSecurityException, IOException
    {
        sqldao.checkDAOStructure();
        IntegrityData id = new IntegrityData(MASTER_PASSWORD.toCharArray());
        id.checkIntegrity(MASTER_PASSWORD.toCharArray());
        sqldao.setIntegrityData(id);
        IntegrityData idOut = sqldao.getIntegrityData();
        idOut.checkIntegrity(MASTER_PASSWORD.toCharArray());
        Assert.assertArrayEquals(id.getCipheredData(), idOut.getCipheredData());
        Assert.assertArrayEquals(id.getDataHash(), idOut.getDataHash());
    }

    @Test
    public void testStoreLoadSecretKey() throws KeyStoreDAOException, UnrecoverableKeyException, GeneralSecurityException, IOException
    {
        final String keyPassword = "key-password";
        final String keyAlias = "key-alias";
        sqldao.checkDAOStructure();
        IntegrityData id = new IntegrityData(MASTER_PASSWORD.toCharArray());
        id.checkIntegrity(MASTER_PASSWORD.toCharArray());
        sqldao.setIntegrityData(id);
        KeyProtection kp = KeyProtection.generateKeyProtection(keyPassword.toCharArray(), id.getSalt());
        KeyStoreEntry kse = new KeyStoreEntry(keyAlias, Date.from(Instant.now()), secretKey, kp, Collections.emptyList(), Collections.emptyList());
        kse.setLockedKeyProtection(kp.getLockedKeyProtection(null));
        sqldao.setEntry(kse);
        KeyStoreEntry kseOut = sqldao.getEntry(keyAlias);
        Assert.assertNotNull(kseOut);
        Assert.assertEquals(keyAlias, kseOut.getAlias());
        KeyProtection kpOut = new KeyProtection(kseOut.getLockedKeyProtection(), null);
        Key k = kseOut.getKey(kpOut);
        Assert.assertTrue(SecretKey.class.isInstance(k));
        Assert.assertArrayEquals(secretKey.getEncoded(), k.getEncoded());
    }
    
    public static class TestSqlKeyStoreDAOFactory extends SqlKeyStoreDAOFactory
    {

        @Override
        public void init() throws KeyStoreDAOException
        {
            // TODO Auto-generated method stub
            super.init();
        }
        
    }
}
