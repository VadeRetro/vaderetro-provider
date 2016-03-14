/**
 * 
 */
package com.vaderetrosecure.keystore.dao.sql;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;

/**
 * @author ahonore
 *
 */
class SqlVRKeyStoreDAO implements VRKeyStoreDAO
{

    @Override
    public int countEntries()
    {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public List<String> getAliases()
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public byte[] getKey(String alias)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Certificate getCertificate(String alias)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Certificate[] getCertificateChain(String alias)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isCertificateEntry(String alias)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isKeyEntry(String alias)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void setKeyEntry(String alias, byte[] key, Certificate[] chain)
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void deleteEntry(String alias)
    {
        // TODO Auto-generated method stub
        
    }
}
