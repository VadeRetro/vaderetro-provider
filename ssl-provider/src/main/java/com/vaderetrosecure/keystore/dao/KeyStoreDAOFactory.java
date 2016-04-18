/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * This class is one of the base classes for implementing a DAO.
 * An implementor of a DAO must do 2 things:
 * <ul>
 * <li>implement the {@linkplain com.vaderetrosecure.keystore.dao.KeyStoreDAO DAO interface}.</li>
 * <li>extend this class to instantiate its own DAO implementation.</li>
 * </ul>
 * <p>
 * The implemented factory is instantiated using the property given with JVM parameters:
 * <pre>
 * {@code java -Dcom.vaderetrosecure.keystore.dao.factory=com.company.MyDAOFactory ...}</pre>
 * if the implementor's factory is {@code com.company.MyDAOFactory}.
 * 
 * @author ahonore
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
    
    /**
     * Return the current KeyStoreDAOFactory instance.
     * If the instance is not available yet, a new factory is created, given the value of the
     * {@code com.vaderetrosecure.keystore.dao.factory} property. Then, the factory is initialized 
     * by calling the {@link #init(Properties)} method.
     * 
     * @return the KeyStoreDAOFactory instance.
     * @throws KeyStoreDAOException if an exception occurs when instantiating or initializing the factory.
     */
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
        Thread.currentThread().getContextClassLoader().getResource("com.vaderetrosecure.keystore.dao.properties");
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(propFile))
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
    
    /**
     * Initialize the KeyStoreDAO object with properties from the {@code com.vaderetrosecure.keystore.dao.properties} file, given in the classpath.
     * You can, for example, specify parameters to an underlying driver.
     * 
     * @param properties properties to initialize the KeyStoreDAO object with.
     * @throws KeyStoreDAOException if an initialization error occurs.
     */
    protected abstract void init(Properties properties) throws KeyStoreDAOException;
    
    /**
     * Give an instantiated KeyStoreDAO object that performs access to real data.
     * 
     * @return an instantiated KeyStoreDAO object. 
     * @throws KeyStoreDAOException if an error occurs when providing an instance.
     */
    public abstract KeyStoreDAO getKeyStoreDAO() throws KeyStoreDAOException;
}
