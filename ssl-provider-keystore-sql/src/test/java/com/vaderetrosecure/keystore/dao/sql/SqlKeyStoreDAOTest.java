/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.UnrecoverableKeyException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Before;
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

    private KeyStoreDAO sqldao;
    private SecretKey secretKey;

    @Before
    public void setUp() throws Exception
    {
        secretKey = new SecretKeySpec("secret key".getBytes(StandardCharsets.US_ASCII), "AES");
        SqlKeyStoreDAOFactory daoFactory = new SqlKeyStoreDAOFactory();
        Properties p = new Properties();
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("com.vaderetrosecure.keystore.dao.properties"))
        {
            p.load(is);
        }
        daoFactory.init(p);
        sqldao = daoFactory.getKeyStoreDAO();
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
}
