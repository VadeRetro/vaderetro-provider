/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.util.List;

/**
 * @author ahonore
 *
 */
public interface KeyStoreDAO
{
    /**
     * Check the DAO structure.
     * Update the underlying data store if needed.
     * 
     * @throws KeyStoreDAOException
     */
    void checkDAOStructure() throws KeyStoreDAOException;
    
    /**
     * Return the number of stored entries.
     * This is the sum of all key and certificate entries.
     * 
     * @return an integer representing the number of entries.
     * @throws KeyStoreDAOException
     */
    int countEntries() throws KeyStoreDAOException;
    
    /**
     * Return the list of all distinct aliases.
     * 
     * @return the list of aliases.
     * @throws KeyStoreDAOException
     */
    List<String> getAliases() throws KeyStoreDAOException;
    
    /**
     * Get aliases that refer to private key/certificate pairs.
     * It is useful for server authentication.
     * 
     * @param keyType the algorithm name used to create the key and certificate pair (i.e.: EC_EC, RSA, DSA...).
     * @return
     * @throws KeyStoreDAOException
     */
    List<String> getAliases(String algorithm) throws KeyStoreDAOException;

    IntegrityData getIntegrityData() throws KeyStoreDAOException;
    
    void setIntegrityData(IntegrityData integrityData) throws KeyStoreDAOException;
    
    KeyStoreEntry getEntry(String alias) throws KeyStoreDAOException;
    
    /**
     * Return all entries that name from the list of names matches the associated entry.
     * 
     * @param name
     * @return
     * @throws KeyStoreDAOException
     */
    List<KeyStoreEntry> getEntries(String name) throws KeyStoreDAOException;
    
    void setEntry(KeyStoreEntry entry) throws KeyStoreDAOException;
    
    void deleteEntry(KeyStoreEntry entry) throws KeyStoreDAOException;
}
