/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * @author ahonore
 *
 */
public interface VRKeyStoreDAO
{
    void checkSchema() throws VRKeyStoreDAOException;
    
    KeyStoreMetaData getMetaData() throws VRKeyStoreDAOException;
    int countEntries() throws VRKeyStoreDAOException;
    List<String> getAliases() throws VRKeyStoreDAOException;
    List<KeyStoreEntry> getKeyStoreEntry(String alias, KeyStoreEntryType keyStoreEntryType) throws VRKeyStoreDAOException;
    List<KeyStoreEntry> getKeyStoreEntry(String alias) throws VRKeyStoreDAOException;
    Date engineGetCreationDate(String alias) throws VRKeyStoreDAOException;
    
    void setMetaData(KeyStoreMetaData keyStoreMetaData) throws VRKeyStoreDAOException;
    void setKeyStoreEntries(Collection<KeyStoreEntry> keyStoreEntries) throws VRKeyStoreDAOException;
    
    void deleteKeyStoreEntry(String alias) throws VRKeyStoreDAOException;
}
