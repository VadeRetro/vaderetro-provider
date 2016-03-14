/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.util.Properties;

/**
 * @author ahonore
 *
 */
public final class VRKeyStoreDAOFactory
{
    private static final String DAO_FACTORY_CLASS_ENV = "com.vaderetro.security.keystore.dao.factory";
    private static final String DAO_FACTORY_PROPERTIES_FILE_ENV = "com.vaderetro.security.keystore.dao.properties";
    private static final Properties DEFAULT_PROPERTIES;
    static
    {
        DEFAULT_PROPERTIES = new Properties();
        DEFAULT_PROPERTIES.setProperty(DAO_FACTORY_CLASS_ENV, "sql factory impl class");
        DEFAULT_PROPERTIES.setProperty(DAO_FACTORY_PROPERTIES_FILE_ENV, "com.vaderetro.security.keystore.dao.properties");
    }
    
    private static VRKeyStoreDAOFactory INSTANCE = null;
    
    private Properties properties;
    
    private VRKeyStoreDAOFactory()
    {
        properties = new Properties(DEFAULT_PROPERTIES);
        String value = System.getenv(DAO_FACTORY_CLASS_ENV);
        if (value != null)
            properties.setProperty(DAO_FACTORY_CLASS_ENV, value);
        value = System.getenv(DAO_FACTORY_PROPERTIES_FILE_ENV);
        if (value != null)
            properties.setProperty(DAO_FACTORY_PROPERTIES_FILE_ENV, value);
    }
    
    public static VRKeyStoreDAOFactory getInstance()
    {
        if (INSTANCE == null)
            INSTANCE = new VRKeyStoreDAOFactory();
        return INSTANCE;
    }
    
    public void init() throws VRKeyStoreDAOException
    {
        // create instance of factory
        
        //  loading properties file
        
        // call init factory with properties
    }
    
    public VRKeyStoreDAO getKeyStoreDAO() throws VRKeyStoreDAOException
    {
        return null;
    }
    
    public void uninit() throws VRKeyStoreDAOException
    {
        
    }
}
