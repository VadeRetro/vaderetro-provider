/**
 * 
 */
package com.vaderetrosecure.ssl;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;

/**
 *
 */
class VRSNIMatcher extends SNIMatcher
{
    private static final Logger LOG = Logger.getLogger(VRSNIMatcher.class);

    private final KeyStoreDAO keyStoreDAO;
    private List<KeyStoreEntry> selectedEntries;

    VRSNIMatcher(KeyStoreDAO keyStoreDAO)
    {
        super(StandardConstants.SNI_HOST_NAME);
        this.keyStoreDAO = keyStoreDAO;
        selectedEntries = new ArrayList<>();
    }

    @Override
    public boolean matches(SNIServerName serverName)
    {
        String name = "";
        if (SNIHostName.class.isInstance(serverName))
            name = ((SNIHostName) serverName).getAsciiName().toLowerCase();
        else
            name = new String(serverName.getEncoded(), StandardCharsets.US_ASCII).toLowerCase();
        
        LOG.debug("SNIServerName: " + name);
        
        try
        {
            selectedEntries = keyStoreDAO.getEntries(name);
            if (LOG.getEffectiveLevel() == Level.DEBUG)
            {
                if (selectedEntries.isEmpty())
                    LOG.debug("no selected entries");
                else
                    LOG.debug("selected entries: " + String.join(",", selectedEntries.stream().map(e -> e.getAlias()).collect(Collectors.toList())));
            }
            return !selectedEntries.isEmpty();
        }
        catch (KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }
        return false;
    }
    
    List<KeyStoreEntry> getSelectedEntries()
    {
        return selectedEntries;
    }
}
