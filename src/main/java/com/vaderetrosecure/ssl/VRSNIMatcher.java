/**
 * 
 */
package com.vaderetrosecure.ssl;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

import com.vaderetrosecure.VRKeyStorageDAO;

/**
 * @author ahonore
 *
 */
class VRSNIMatcher extends SNIMatcher
{
    private final VRKeyStorageDAO keyStorageDAO;

    VRSNIMatcher(VRKeyStorageDAO keyStorageDAO)
    {
        super(StandardConstants.SNI_HOST_NAME);
        this.keyStorageDAO = keyStorageDAO;
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
