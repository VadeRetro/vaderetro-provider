/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.UnrecoverableKeyException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;


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
        sqldao.createSchema();
    }

    @Test
    public void testStoreLoadMetaData() throws KeyStoreDAOException, UnrecoverableKeyException, GeneralSecurityException, IOException
    {
        sqldao.createSchema();
        KeyStoreMetaData ksemd = KeyStoreMetaData.generate(MASTER_PASSWORD.toCharArray());
        ksemd.checkIntegrity(MASTER_PASSWORD.toCharArray());
        sqldao.setMetaData(ksemd);
        KeyStoreMetaData ksemdOut = sqldao.getMetaData();
        ksemdOut.checkIntegrity(MASTER_PASSWORD.toCharArray());
        Assert.assertArrayEquals(ksemd.getKeyIV(), ksemdOut.getKeyIV());
        Assert.assertArrayEquals(ksemd.getKeyIVHash(), ksemdOut.getKeyIVHash());
    }

    @Test
    public void testStoreLoadSecretKey() throws KeyStoreDAOException, UnrecoverableKeyException, GeneralSecurityException, IOException
    {
        final String keyPassword = "key-password";
        sqldao.createSchema();
        KeyStoreMetaData ksemd = KeyStoreMetaData.generate(MASTER_PASSWORD.toCharArray());
        ksemd.checkIntegrity(MASTER_PASSWORD.toCharArray());
        sqldao.setMetaData(ksemd);
        KeyStoreEntry kse = new KeyStoreEntry("key-alias", KeyStoreEntryType.SECRET_KEY, 0, Date.from(Instant.now()), secretKey.getAlgorithm(), ksemd.cipherKeyEntry(keyPassword.toCharArray(), secretKey.getEncoded()));
        sqldao.setKeyStoreEntries(Collections.singletonList(kse));
        List<KeyStoreEntry> entries = sqldao.getKeyStoreEntry("key-alias");
        Assert.assertEquals(1, entries.size());
        KeyStoreEntry kseOut = entries.get(0);
        SecretKey skOut = new SecretKeySpec(ksemd.decipherKeyEntry(keyPassword.toCharArray(), kseOut.getData()), kseOut.getAlgorithm());
        Assert.assertArrayEquals(secretKey.getEncoded(), skOut.getEncoded());
    }
}
