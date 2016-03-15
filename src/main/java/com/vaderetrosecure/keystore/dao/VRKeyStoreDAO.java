/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

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
    void setKeyStoreEntry(KeyStoreEntry keyStoreEntry) throws VRKeyStoreDAOException;
    
    void deleteKeyStoreEntry(String alias) throws VRKeyStoreDAOException;
}
