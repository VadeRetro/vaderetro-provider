/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.io.IOException;
import java.io.InputStream;
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
 * This class is a part of the implementation of the SQL DAO.
 * <p>
 * This factory instantiates the {@code SqlKeyStoreDAO} class by:
 * <ul>
 * <li>loading the SQL driver</li>
 * <li>creating a connection pool initialized from user properties</li>
 * <li>creating the {@code DataSource} object</li>
 * <li>instantiating a {@code KeyStoreDAO} object, giving the {@code DataSource} object. 
 * </ul>
 * <p>
 * This factory must be given some properties by adding the file {@code com.vaderetrosecure.keystore.dao.properties}
 * to the class path. At least the following properties must be specified:
 * <ul>
 * <li>{@code driverClassName}: the full SQL driver class name (for example {@code driverClassName = com.mysql.jdbc.Driver} for the MySQL driver)</li>
 * <li>{@code url}: the URL of the database connection (for example {@code url = jdbc:mysql://myserver.com/DataBase} for a MySQL connection)</li>
 * <li>{@code user}: the user name to connect to the database</li>
 * <li>{@code password}: the password of the user.</li>
 * </ul>
 * <p>
 * This implementation uses the <a href="https://commons.apache.org/proper/commons-dbcp/">Apache DBCP 2 component</a> to
 * create connection pools and {@code DataSource} objects. So, all configuration parameters defined 
 * <a href="https://commons.apache.org/proper/commons-dbcp/configuration.html">here</a> can be used in this factory.
 * 
 * @author ahonore
 * @see com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory
 * @see com.vaderetrosecure.keystore.dao.sql.SqlKeyStoreDAO
 */
public class SqlKeyStoreDAOFactory extends KeyStoreDAOFactory
{
    private static final Logger LOG = Logger.getLogger(SqlKeyStoreDAOFactory.class);
    
    private static final String DAO_FACTORY_PROPERTIES_FILE_NAME = "com.vaderetrosecure.keystore.dao.properties";

    private KeyStoreDAO keyStoreDAO;
    
    public SqlKeyStoreDAOFactory()
    {
        keyStoreDAO = null;
    }

    @Override
    protected void init() throws KeyStoreDAOException
    {
        try
        {
            Properties prop = loadProperties();
            DataSource dataSource = createDataSource(prop);
            keyStoreDAO = new SqlKeyStoreDAO(dataSource, new StructureManager(dataSource));
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
    
    private Properties loadProperties()
    {
        //  loading properties file
        Properties prop = new Properties();
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(DAO_FACTORY_PROPERTIES_FILE_NAME))
        {
            if (is == null)
                LOG.warn("unable to load '" + DAO_FACTORY_PROPERTIES_FILE_NAME + "' file");
            else
                prop.load(is);
            return prop;
        }
        catch (IOException e)
        {
            LOG.warn(e);
            LOG.debug(e, e);
        }
        
        return prop;
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
