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
public interface KeyStoreDAO
{
    /**
     * Create tables of the databases.
     * Be aware that this method first try to delete all tables if exist and create the database from scratch.
     * 
     * @throws KeyStoreDAOException
     */
    void createSchema() throws KeyStoreDAOException;
    
    KeyStoreMetaData getMetaData() throws KeyStoreDAOException;
    int countEntries() throws KeyStoreDAOException;
    List<String> getAliases() throws KeyStoreDAOException;
    List<String> getAliases(String keyType) throws KeyStoreDAOException;
    List<KeyStoreEntry> getKeyStoreEntry(String alias, KeyStoreEntryType keyStoreEntryType) throws KeyStoreDAOException;
    List<KeyStoreEntry> getKeyStoreEntry(String alias) throws KeyStoreDAOException;
    List<KeyStoreEntry> getKeyStoreEntriesByName(String name) throws KeyStoreDAOException;
    Date engineGetCreationDate(String alias) throws KeyStoreDAOException;
    
    void setMetaData(KeyStoreMetaData keyStoreMetaData) throws KeyStoreDAOException;
    void setKeyStoreEntries(Collection<KeyStoreEntry> keyStoreEntries) throws KeyStoreDAOException;
    
    void deleteEntries(Collection<String> aliases) throws KeyStoreDAOException;
}
