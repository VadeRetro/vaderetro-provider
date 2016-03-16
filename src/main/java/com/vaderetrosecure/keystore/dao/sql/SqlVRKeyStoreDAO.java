/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOException;

/**
 * @author ahonore
 *
 */
class SqlVRKeyStoreDAO implements VRKeyStoreDAO
{
    private DataSource dataSource;
    
    SqlVRKeyStoreDAO(DataSource dataSource)
    {
        this.dataSource = dataSource;
    }

    @Override
    public void checkSchema() throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public KeyStoreMetaData getMetaData() throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int countEntries() throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public List<String> getAliases() throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<KeyStoreEntry> getKeyStoreEntry(String alias, KeyStoreEntryType keyStoreEntryType) throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<KeyStoreEntry> getKeyStoreEntry(String alias) throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void setMetaData(KeyStoreMetaData keyStoreMetaData) throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void setKeyStoreEntries(Collection<KeyStoreEntry> keyStoreEntries) throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void deleteKeyStoreEntry(String alias) throws VRKeyStoreDAOException
    {
        // TODO Auto-generated method stub
        
    }
}
