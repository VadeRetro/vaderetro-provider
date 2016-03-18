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
public abstract class VRKeyStoreDAOFactory
{
    private static final Logger LOG = Logger.getLogger(VRKeyStoreDAOFactory.class);

    public static final String DAO_FACTORY_CLASS_NAME = "com.vaderetrosecure.keystore.dao.factory";
    
    private static final String DAO_FACTORY_PROPERTIES_FILE_NAME = "com.vaderetrosecure.keystore.dao.properties";
    private static VRKeyStoreDAOFactory INSTANCE = null;
    
    protected VRKeyStoreDAOFactory()
    {
    }
    
    public static VRKeyStoreDAOFactory getInstance() throws VRKeyStoreDAOException
    {
        if (INSTANCE != null)
            return INSTANCE;
        
        // create instance of factory
        String factoryClassStr = System.getProperty(DAO_FACTORY_CLASS_NAME, VRKeyStoreDAOFactory.class.getName());
        if (factoryClassStr == null)
            throw new VRKeyStoreDAOException("system property '" + DAO_FACTORY_CLASS_NAME + "' not set");

        VRKeyStoreDAOFactory factory = null;
        try
        {
            @SuppressWarnings("unchecked")
            Class<VRKeyStoreDAOFactory> cl = (Class<VRKeyStoreDAOFactory>) Class.forName(factoryClassStr);
            factory = cl.newInstance();
            Properties prop = loadProperties();
            factory.init(prop);
        }
        catch (ClassNotFoundException | InstantiationException | IllegalAccessException e)
        {
            LOG.fatal(e, e);
            throw new VRKeyStoreDAOException(e);
        }
        
        INSTANCE = factory;
        return INSTANCE;
    }
    
    private static Properties loadProperties() throws VRKeyStoreDAOException
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
            throw new VRKeyStoreDAOException(e);
        }
    }
    
    protected abstract void init(Properties properties) throws VRKeyStoreDAOException;
    
    public abstract VRKeyStoreDAO getKeyStoreDAO() throws VRKeyStoreDAOException;
}
