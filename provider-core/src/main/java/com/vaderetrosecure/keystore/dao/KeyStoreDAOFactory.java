/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

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
 */
public abstract class KeyStoreDAOFactory
{
    private static final Logger LOG = Logger.getLogger(KeyStoreDAOFactory.class);

    public static final String DAO_FACTORY_CLASS_NAME = "com.vaderetrosecure.keystore.dao.factory";
    
    private static KeyStoreDAOFactory INSTANCE = null;
    
    protected KeyStoreDAOFactory()
    {
    }
    
    /**
     * Return the current KeyStoreDAOFactory instance.
     * If the instance is not available yet, a new factory is created, given the value of the
     * {@code com.vaderetrosecure.keystore.dao.factory} property. Then, the factory is initialized 
     * by calling the {@link #init()} method.
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
            factory.init();
        }
        catch (ClassNotFoundException | InstantiationException | IllegalAccessException e)
        {
            LOG.fatal(e, e);
            throw new KeyStoreDAOException(e);
        }
        
        INSTANCE = factory;
        return INSTANCE;
    }
    
    /**
     * Initialize the {@code KeyStoreDAO} object.
     * The implementor can use this method to load parameters needed by an underlying driver.
     * 
     * @throws KeyStoreDAOException if an initialization error occurs.
     */
    protected abstract void init() throws KeyStoreDAOException;
    
    /**
     * Give an instantiated KeyStoreDAO object that performs access to real data.
     * 
     * @return an instantiated KeyStoreDAO object. 
     * @throws KeyStoreDAOException if an error occurs when providing an instance.
     */
    public abstract KeyStoreDAO getKeyStoreDAO() throws KeyStoreDAOException;
}
