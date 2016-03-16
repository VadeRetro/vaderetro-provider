/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.util.Properties;

import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class SqlVRKeyStoreDAOFactory extends VRKeyStoreDAOFactory
{

    @Override
    protected void init(Properties properties) throws VRKeyStoreDAOException
    {
    }

    @Override
    public VRKeyStoreDAO getKeyStoreDAO() throws VRKeyStoreDAOException
    {
        return null;
    }
}
