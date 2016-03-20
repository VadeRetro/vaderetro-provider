/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * @author ahonore
 *
 */
public abstract class KeyStoreDAOFactory
{
    private static final Logger LOG = Logger.getLogger(KeyStoreDAOFactory.class);

    public static final String DAO_FACTORY_CLASS_NAME = "com.vaderetrosecure.keystore.dao.factory";
    
    private static final String DAO_FACTORY_PROPERTIES_FILE_NAME = "com.vaderetrosecure.keystore.dao.properties";
    private static KeyStoreDAOFactory INSTANCE = null;
    
    protected KeyStoreDAOFactory()
    {
    }
    
    public static KeyStoreDAOFactory getInstance() throws KeyStoreDAOException
    {
        if (INSTANCE != null)
            return INSTANCE;
        
        // create instance of factory
        String factoryClassStr = System.getProperty(DAO_FACTORY_CLASS_NAME, KeyStoreDAOFactory.class.getName());
        if (factoryClassStr == null)
            throw new KeyStoreDAOException("system property '" + DAO_FACTORY_CLASS_NAME + "' not set");

        KeyStoreDAOFactory factory = null;
        try
        {
            @SuppressWarnings("unchecked")
            Class<KeyStoreDAOFactory> cl = (Class<KeyStoreDAOFactory>) Class.forName(factoryClassStr);
            factory = cl.newInstance();
            Properties prop = loadProperties();
            factory.init(prop);
        }
        catch (ClassNotFoundException | InstantiationException | IllegalAccessException e)
        {
            LOG.fatal(e, e);
            throw new KeyStoreDAOException(e);
        }
        
        INSTANCE = factory;
        return INSTANCE;
    }
    
    private static Properties loadProperties() throws KeyStoreDAOException
    {
        //  loading properties file
        String propFile = System.getProperty(DAO_FACTORY_PROPERTIES_FILE_NAME, "com.vaderetrosecure.keystore.dao.properties");
        Properties prop = new Properties();
        try (InputStream is = ClassLoader.getSystemResourceAsStream(propFile))
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
            throw new KeyStoreDAOException(e);
        }
    }
    
    protected abstract void init(Properties properties) throws KeyStoreDAOException;
    
    public abstract KeyStoreDAO getKeyStoreDAO() throws KeyStoreDAOException;
}
