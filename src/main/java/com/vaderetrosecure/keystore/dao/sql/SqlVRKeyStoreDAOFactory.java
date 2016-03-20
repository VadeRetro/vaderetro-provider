/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.util.Properties;

import javax.sql.DataSource;

import org.apache.commons.dbcp2.ConnectionFactory;
import org.apache.commons.dbcp2.DriverManagerConnectionFactory;
import org.apache.commons.dbcp2.PoolableConnection;
import org.apache.commons.dbcp2.PoolableConnectionFactory;
import org.apache.commons.dbcp2.PoolingDataSource;
import org.apache.commons.pool2.ObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class SqlVRKeyStoreDAOFactory extends KeyStoreDAOFactory
{
    private final static Logger LOG = Logger.getLogger(SqlVRKeyStoreDAOFactory.class);
    
    private KeyStoreDAO keyStoreDAO;
    
    public SqlVRKeyStoreDAOFactory()
    {
        keyStoreDAO = null;
    }

    @Override
    protected void init(Properties properties) throws KeyStoreDAOException
    {
        try
        {
            keyStoreDAO = new SqlVRKeyStoreDAO(createDataSource(properties));
        }
        catch (ClassNotFoundException e)
        {
            LOG.fatal(e, e);
            throw new KeyStoreDAOException(e);
        }
    }

    @Override
    public KeyStoreDAO getKeyStoreDAO() throws KeyStoreDAOException
    {
        return keyStoreDAO;
    }

    private DataSource createDataSource(Properties properties) throws ClassNotFoundException 
    {
        String driver = properties.getProperty("driverClassName", "");
        Class.forName(driver);
        String url = properties.getProperty("url", "");

        ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(url, properties);
        PoolableConnectionFactory poolableConnectionFactory = new PoolableConnectionFactory(connectionFactory, null);
        ObjectPool<PoolableConnection> connectionPool = new GenericObjectPool<>(poolableConnectionFactory);
        poolableConnectionFactory.setPool(connectionPool);
        return new PoolingDataSource<>(connectionPool);
    }
}
