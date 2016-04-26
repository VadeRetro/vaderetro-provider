/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;


/**
 *
 */
public class SqlKeyStoreDAOTest
{
    private static final String MASTER_PASSWORD = "master-password";
    private static final String KEY_PASSWORD = "key-password";

    private static IntegrityData integrityData;
    private static KeyStoreEntry keyStoreEntry;
    private KeyStoreDAO sqldao;
    private DataSource mockDataSource;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private StructureManager mockStructureManager;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        integrityData = new IntegrityData(MASTER_PASSWORD.toCharArray());
        SecretKey secretKey = new SecretKeySpec("secret key".getBytes(StandardCharsets.US_ASCII), "AES");
        KeyProtection kp = KeyProtection.generateKeyProtection(KEY_PASSWORD.toCharArray(), integrityData.getSalt());
        keyStoreEntry = new KeyStoreEntry("key-alias", Date.from(Instant.now()), secretKey, kp, Collections.emptyList(), Collections.emptyList());
        keyStoreEntry.setLockedKeyProtection(kp.getLockedKeyProtection(null));
        
        
//        daoFactory = new TestSqlKeyStoreDAOFactory();
//        daoFactory.init();
    }
    
    @Before
    public void setUp() throws Exception
    {
//        sqldao = daoFactory.getKeyStoreDAO();
//        dropTables(((SqlKeyStoreDAO) sqldao).getDataSource());
        
        mockDataSource = mock(DataSource.class);
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        when(mockDataSource.getConnection()).thenReturn(mockConnection);
        
        mockStructureManager = mock(StructureManager.class);
        
        sqldao = new SqlKeyStoreDAO(mockDataSource, mockStructureManager);
    }
    
    @Test
    public void testCheckDAOStructure() throws KeyStoreDAOException
    {
        when(mockStructureManager.versionsTableExists()).thenReturn(true);
        sqldao.checkDAOStructure();
    }
    
    @Test(expected=KeyStoreDAOException.class)
    public void testCountEntries() throws KeyStoreDAOException, SQLException
    {
        ResultSet mockResultSetNoNext = mock(ResultSet.class);
        when(mockResultSetNoNext.next()).thenReturn(false);
        
        ResultSet mockResultSet = mock(ResultSet.class);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getInt(anyInt())).thenReturn(10).thenThrow(new SQLException());
        
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSetNoNext).thenReturn(mockResultSet);
        
        Assert.assertEquals(0, sqldao.countEntries());
        Assert.assertEquals(10, sqldao.countEntries());
        sqldao.countEntries();
    }
    
    @Test(expected=KeyStoreDAOException.class)
    public void testGetAliases() throws KeyStoreDAOException, SQLException
    {
        ResultSet mockResultSetNoNext = mock(ResultSet.class);
        when(mockResultSetNoNext.next()).thenReturn(false);
        
        ResultSet mockResultSet = mock(ResultSet.class);
        when(mockResultSet.next()).thenReturn(true).thenReturn(true).thenReturn(false);
        when(mockResultSet.getString(anyInt())).thenReturn("alias-1").thenReturn("alias-2");
        
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSetNoNext).thenReturn(mockResultSet).thenThrow(new SQLException());
        
        Assert.assertArrayEquals(new String[]{}, sqldao.getAliases().toArray(new String[]{}));
        Assert.assertArrayEquals(new String[]{ "alias-1", "alias-2" }, sqldao.getAliases().toArray(new String[]{}));
        sqldao.getAliases();
    }
    
    @Test(expected=KeyStoreDAOException.class)
    public void testGetIntegrityData() throws KeyStoreDAOException, SQLException
    {
        ResultSet mockResultSetNoNext = mock(ResultSet.class);
        when(mockResultSetNoNext.next()).thenReturn(false);
        
        ResultSet mockResultSet = mock(ResultSet.class);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(eq("salt"))).thenReturn(EncodingTools.b64Encode(integrityData.getSalt()));
        when(mockResultSet.getString(eq("iv"))).thenReturn(EncodingTools.b64Encode(integrityData.getIV()));
        when(mockResultSet.getString(eq("data"))).thenReturn(EncodingTools.b64Encode(integrityData.getCipheredData()));
        when(mockResultSet.getString(eq("data_hash"))).thenReturn(EncodingTools.hexStringEncode(integrityData.getDataHash()));
        
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSetNoNext).thenReturn(mockResultSet).thenThrow(new SQLException());
        
        Assert.assertNull(sqldao.getIntegrityData());
        
        IntegrityData id = sqldao.getIntegrityData();
        Assert.assertArrayEquals(integrityData.getSalt(), id.getSalt());
        Assert.assertArrayEquals(integrityData.getCipheredData(), id.getCipheredData());
        Assert.assertArrayEquals(integrityData.getDataHash(), id.getDataHash());
        Assert.assertArrayEquals(integrityData.getIV(), id.getIV());
        
        sqldao.getIntegrityData();
    }
    
    @Test
    public void testSetIntegrityData() throws KeyStoreDAOException, SQLException
    {
        ArgumentCaptor<Integer> idLongCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> idStringCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Long> longCaptor = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<String> strCaptor = ArgumentCaptor.forClass(String.class);
        
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        
        sqldao.setIntegrityData(integrityData);
        verify(mockPreparedStatement, times(2)).setLong(idLongCaptor.capture(), longCaptor.capture());
        verify(mockPreparedStatement, times(4)).setString(idStringCaptor.capture(), strCaptor.capture());
        
        idLongCaptor.getAllValues().forEach(v -> Assert.assertEquals(1, v.intValue()));
        longCaptor.getAllValues().forEach(v -> Assert.assertEquals(1L, v.longValue()));
        
        List<Integer> ids = idStringCaptor.getAllValues();
        List<String> strings = strCaptor.getAllValues();
        Assert.assertEquals(2, ids.get(0).intValue());
        Assert.assertArrayEquals(integrityData.getSalt(), EncodingTools.b64Decode(strings.get(0)));
        Assert.assertEquals(3, ids.get(1).intValue());
        Assert.assertArrayEquals(integrityData.getIV(), EncodingTools.b64Decode(strings.get(1)));
        Assert.assertEquals(4, ids.get(2).intValue());
        Assert.assertArrayEquals(integrityData.getCipheredData(), EncodingTools.b64Decode(strings.get(2)));
        Assert.assertEquals(5, ids.get(3).intValue());
        Assert.assertArrayEquals(integrityData.getDataHash(), EncodingTools.hexStringDecode(strings.get(3)));
    }
    
    @Test(expected=KeyStoreDAOException.class)
    public void testSetIntegrityDataException() throws KeyStoreDAOException, SQLException
    {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement).thenThrow(new SQLException());
        
        sqldao.setIntegrityData(integrityData);
    }
    
    @Test
    public void testGetEntry() throws KeyStoreDAOException, SQLException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        ResultSet mockResultSetNoNext = mock(ResultSet.class);
        when(mockResultSetNoNext.next()).thenReturn(false);
        
        ResultSet mockResultSet = mock(ResultSet.class);
        when(mockResultSet.next()).thenReturn(true).thenReturn(false).thenReturn(false);
        when(mockResultSet.getString(eq("protection_key"))).thenReturn(EncodingTools.b64Encode(keyStoreEntry.getLockedKeyProtection().getCipheredKey()));
        when(mockResultSet.getString(eq("protection_param"))).thenReturn(EncodingTools.b64Encode(keyStoreEntry.getLockedKeyProtection().getIV()));
        when(mockResultSet.getString(eq("alias"))).thenReturn(keyStoreEntry.getAlias());
        when(mockResultSet.getLong(eq("creation_date"))).thenReturn(keyStoreEntry.getCreationDate().getTime());
        when(mockResultSet.getInt(eq("entry_type"))).thenReturn(keyStoreEntry.getEntryType().ordinal());
        when(mockResultSet.getString(eq("algorithm"))).thenReturn(keyStoreEntry.getAlgorithm());
        when(mockResultSet.getString(eq("data"))).thenReturn(EncodingTools.b64Encode(keyStoreEntry.getEntryData()));
        
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSetNoNext).thenReturn(mockResultSet);
        
        Assert.assertNull(sqldao.getEntry("key-alias"));
        
        KeyStoreEntry kse = sqldao.getEntry("key-alias");
        Assert.assertEquals(keyStoreEntry.getCreationDate(), kse.getCreationDate());
        Assert.assertEquals(keyStoreEntry.getEntryType(), kse.getEntryType());
        Assert.assertEquals(keyStoreEntry.getAlgorithm(), kse.getAlgorithm());
        Assert.assertArrayEquals(keyStoreEntry.getEntryData(), kse.getEntryData());
        Assert.assertArrayEquals(keyStoreEntry.getLockedKeyProtection().getCipheredKey(), kse.getLockedKeyProtection().getCipheredKey());
        Assert.assertArrayEquals(keyStoreEntry.getLockedKeyProtection().getIV(), kse.getLockedKeyProtection().getIV());
        Assert.assertArrayEquals(keyStoreEntry.getCertificateChain().toArray(new CertificateData[]{}), kse.getCertificateChain().toArray(new CertificateData[]{}));
        Assert.assertArrayEquals(keyStoreEntry.getNames().toArray(new String[]{}), kse.getNames().toArray(new String[]{}));
    }
    
    @Test(expected=KeyStoreDAOException.class)
    public void testGetEntryException() throws KeyStoreDAOException, SQLException
    {
        when(mockDataSource.getConnection()).thenThrow(new SQLException());
        
        sqldao.getEntry("alias");
    }
    
    @Test
    public void testSetEntry() throws KeyStoreDAOException, SQLException
    {
        ArgumentCaptor<Integer> idLongCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> idStringCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Integer> idIntCaptor = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Long> longCaptor = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<String> strCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> intCaptor = ArgumentCaptor.forClass(Integer.class);
        
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        
        sqldao.setEntry(keyStoreEntry);
        verify(mockPreparedStatement, times(1)).setLong(idLongCaptor.capture(), longCaptor.capture());
        verify(mockPreparedStatement, times(1)).setInt(idIntCaptor.capture(), intCaptor.capture());
        verify(mockPreparedStatement, times(6)).setString(idStringCaptor.capture(), strCaptor.capture());
        
        Assert.assertEquals(2, idIntCaptor.getValue().intValue());
        Assert.assertEquals(keyStoreEntry.getEntryType().ordinal(), intCaptor.getValue().intValue());

        Assert.assertEquals(4, idLongCaptor.getValue().intValue());
        Assert.assertEquals(keyStoreEntry.getCreationDate(), new Date(longCaptor.getValue().longValue()));
        
        List<Integer> ids = idStringCaptor.getAllValues();
        List<String> strings = strCaptor.getAllValues();
        Assert.assertEquals(1, ids.get(0).intValue());
        Assert.assertEquals(EncodingTools.toSHA2(keyStoreEntry.getAlias()), strings.get(0));
        Assert.assertEquals(3, ids.get(1).intValue());
        Assert.assertEquals(keyStoreEntry.getAlias(), strings.get(1));
        Assert.assertEquals(5, ids.get(2).intValue());
        Assert.assertEquals(keyStoreEntry.getAlgorithm(), strings.get(2));
        Assert.assertEquals(6, ids.get(3).intValue());
        Assert.assertArrayEquals(keyStoreEntry.getEntryData(), EncodingTools.b64Decode(strings.get(3)));
        Assert.assertEquals(7, ids.get(4).intValue());
        Assert.assertArrayEquals(keyStoreEntry.getLockedKeyProtection().getCipheredKey(), EncodingTools.b64Decode(strings.get(4)));
        Assert.assertEquals(8, ids.get(5).intValue());
        Assert.assertArrayEquals(keyStoreEntry.getLockedKeyProtection().getIV(), EncodingTools.b64Decode(strings.get(5)));
    }
    
    @Test(expected=KeyStoreDAOException.class)
    public void testSetEntryException() throws KeyStoreDAOException, SQLException
    {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement).thenThrow(new SQLException());
        
        sqldao.setEntry(keyStoreEntry);
    }
}
