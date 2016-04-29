/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import static org.mockito.Mockito.mock;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;

/**
 * 
 */
public class SqlKeyStoreDAOFactoryTest
{
    private MockSqlDAOFactory daoFactory;

    @Before
    public void setUp() throws Exception
    {
        daoFactory = new MockSqlDAOFactory();
    }

    @Test
    public void testInit() throws KeyStoreDAOException
    {
        daoFactory.init();
        
        Assert.assertNotNull(daoFactory.getKeyStoreDAO());
        Assert.assertNotNull(((SqlKeyStoreDAO) daoFactory.getKeyStoreDAO()).getDataSource());
    }

    public static class MockSqlDriver implements Driver
    {

        @Override
        public Connection connect(String url, Properties info) throws SQLException
        {
            return mock(Connection.class);
        }

        @Override
        public boolean acceptsURL(String url) throws SQLException
        {
            return url.startsWith("jdbc:mockdriver://");
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException
        {
            return new DriverPropertyInfo[]{};
        }

        @Override
        public int getMajorVersion()
        {
            return 1;
        }

        @Override
        public int getMinorVersion()
        {
            return 0;
        }

        @Override
        public boolean jdbcCompliant()
        {
            return false;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException
        {
            return mock(Logger.class);
        }
    }
    
    public static class MockSqlDAOFactory extends SqlKeyStoreDAOFactory
    {

        @Override
        protected void init() throws KeyStoreDAOException
        {
            // TODO Auto-generated method stub
            super.init();
        }
    }
}
