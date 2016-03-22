/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.nio.charset.StandardCharsets;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;

/**
 * @author ahonore
 *
 */
class VRSNIMatcher extends SNIMatcher
{
    private final static Logger LOG = Logger.getLogger(VRSNIMatcher.class);

    private final KeyStoreDAO keyStoreDAO;
    private String selectedAlias;

    VRSNIMatcher(KeyStoreDAO keyStoreDAO)
    {
        super(StandardConstants.SNI_HOST_NAME);
        this.keyStoreDAO = keyStoreDAO;
        selectedAlias = null;
    }

    @Override
    public boolean matches(SNIServerName serverName)
    {
        String name = "";
        if (SNIHostName.class.isInstance(serverName))
            name = ((SNIHostName) serverName).getAsciiName().toLowerCase();
        else
            name = new String(serverName.getEncoded(), StandardCharsets.US_ASCII).toLowerCase();
        
        try
        {
            selectedAlias = keyStoreDAO.getAliasFromCertificateName(name);
            return selectedAlias != null;
        }
        catch (KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }
        return false;
    }
    
    String getSelectedAlias()
    {
        return selectedAlias;
    }
}
