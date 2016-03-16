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

import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class SqlVRKeyStoreDAOFactory extends VRKeyStoreDAOFactory
{
    private final static Logger LOG = Logger.getLogger(SqlVRKeyStoreDAOFactory.class);

    static
    {
    	System.setProperty(VRKeyStoreDAOFactory.DAO_FACTORY_CLASS_PROPERTY_NAME, SqlVRKeyStoreDAOFactory.class.getName());
    }
    
    private VRKeyStoreDAO keyStoreDAO;
    
    public SqlVRKeyStoreDAOFactory()
    {
        keyStoreDAO = null;
    }

    @Override
    protected void init(Properties properties) throws VRKeyStoreDAOException
    {
        try
        {
            keyStoreDAO = new SqlVRKeyStoreDAO(createDataSource(properties));
        }
        catch (ClassNotFoundException e)
        {
            LOG.fatal(e, e);
            throw new VRKeyStoreDAOException(e);
        }
    }

    @Override
    public VRKeyStoreDAO getKeyStoreDAO() throws VRKeyStoreDAOException
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
