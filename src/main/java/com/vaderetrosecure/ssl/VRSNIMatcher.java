/**
 * 
 */
package com.vaderetrosecure.ssl;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;

/**
 * @author ahonore
 *
 */
class VRSNIMatcher extends SNIMatcher
{
    private final VRKeyStoreDAO keyStoreDAO;

    VRSNIMatcher(VRKeyStoreDAO keyStoreDAO)
    {
        super(StandardConstants.SNI_HOST_NAME);
        this.keyStoreDAO = keyStoreDAO;
    }

    @Override
    public boolean matches(SNIServerName serverName)
    {
        return false;
    }
    
    String getSelectedAlias()
    {
        return null;
    }
}
