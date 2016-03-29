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
    
    IntegrityData getIntegrityData() throws KeyStoreDAOException;
    
    int countEntries() throws KeyStoreDAOException;
    
    List<String> getAliases() throws KeyStoreDAOException;
    
    Version getVersion() throws KeyStoreDAOException;
    
    /**
     * Get aliases that refer to private key/certificate pairs.
     * It is useful for server authentication.
     * 
     * @param keyType
     * @return
     * @throws KeyStoreDAOException
     */
    List<String> getAuthenticationAliases(String keyType) throws KeyStoreDAOException;
    
    List<KeyEntry> getKeyEntry(String alias, KeyEntryType keyStoreEntryType) throws KeyStoreDAOException;
    
    List<KeyEntry> getKeyEntry(String alias) throws KeyStoreDAOException;
    
    List<KeyEntry> getKeyEntriesByName(String name) throws KeyStoreDAOException;
    
    KeyProtection getKeyProtection(String alias) throws KeyStoreDAOException;
    
    /**
     * Return the date of the creation of the entry in the structure.
     * 
     * @param alias
     * @return
     * @throws KeyStoreDAOException
     */
    Date getCreationDate(String alias) throws KeyStoreDAOException;
    
    void setIntegrityData(IntegrityData integrityData) throws KeyStoreDAOException;
    
    void setKeyEntries(Collection<KeyEntry> keyEntries) throws KeyStoreDAOException;
    
    void setKeyProtections(Collection<KeyProtection> keyProtections) throws KeyStoreDAOException;
    
    void deleteEntries(Collection<String> aliases) throws KeyStoreDAOException;
}
