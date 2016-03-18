/**
 * 
 */
package com.vaderetrosecure;

import static org.junit.Assert.*;

import java.security.Security;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;

import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class VadeRetroProviderTest
{
    private VadeRetroProvider vrProvider = new VadeRetroProvider();
    
    @Before
    public void setUp() throws Exception
    {
        Security.addProvider(vrProvider);
    }

    @Test
    public void testGetDummyKeystore()
    {
        System.setProperty(VRKeyStoreDAOFactory.DAO_FACTORY_CLASS_NAME, "");
        fail("Not yet implemented");
    }

    public static class DummyVRKeyStoreDAOFactory extends VRKeyStoreDAOFactory
    {
        @Override
        protected void init(Properties properties) throws VRKeyStoreDAOException
        {
            // TODO Auto-generated method stub
            
        }

        @Override
        public VRKeyStoreDAO getKeyStoreDAO() throws VRKeyStoreDAOException
        {
            // TODO Auto-generated method stub
            return null;
        }
    }
}
