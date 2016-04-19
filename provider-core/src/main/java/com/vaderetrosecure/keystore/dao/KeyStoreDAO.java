/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.util.List;

/**
 * This class is one of the base classes for implementing a DAO.
 * An implementor of a DAO must do 2 things:
 * <ul>
 * <li>implement this DAO interface.</li>
 * <li>extend the {@linkplain com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory} class to instantiate its own DAO implementation.</li>
 * </ul>
 * <p>
 * This class controls the storage of key store entries. Each {@code VRKeyStoreSpi}, {@code SNIX509ExtendedKeyManager} or 
 * {@code TLSSSLContextSpi} object uses instances of this class as its underlying layer for storage accesses.
 * 
 * @author ahonore
 * @see com.vaderetrosecure.keystore.VRKeyStoreSpi
 * @see com.vaderetrosecure.ssl.SNIX509ExtendedKeyManager
 * @see com.vaderetrosecure.ssl.TLSSSLContextSpi
 */
public interface KeyStoreDAO
{
    /**
     * Check the DAO structure.
     * This method is called at each initialization of the key store or key manager factory. It checks the underlying implementation 
     * structure, such as database tables or files to preserve its consistency, and eventually fixes broken data. It must be able to
     * update the underlying data store to a newer version if needed. The version management is the responsibility of the DAO implementation.
     * 
     * @throws KeyStoreDAOException if the check failed, consistency can not be preserved or update was badly performed.
     * @see com.vaderetrosecure.keystore.VRKeyStoreSpi#engineLoad(java.io.InputStream, char[])
     * @see com.vaderetrosecure.ssl.VRKeyManagerFactorySpi#engineInit(KeyStore, char[])
     */
    void checkDAOStructure() throws KeyStoreDAOException;
    
    /**
     * Return the number of stored entries.
     * This is the sum of all key and trusted certificate entries.
     * 
     * @return an integer representing the number of entries.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     */
    int countEntries() throws KeyStoreDAOException;
    
    /**
     * Return the list of all aliases of key store entries.
     * 
     * @return the list of aliases.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     */
    List<String> getAliases() throws KeyStoreDAOException;
    
    /**
     * Return aliases selected by their algorithm.
     * The algorithm is defined at the KeyStoreEntry object construction.
     * 
     * @param algorithm the algorithm name used to create the key and certificate pair (i.e.: EC_EC, RSA, DSA...).
     * @return the list of aliases, or an empty list if there is not alias for the algorithm.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     * @see com.vaderetrosecure.keystore.dao.KeyStoreEntry
     */
    List<String> getAliases(String algorithm) throws KeyStoreDAOException;

    /**
     * Return the {@code IntegrityData} object.
     * It is used to check integrity and provides global ciphering data. Only one instance 
     * may be stored. If the object is {@code null}, it generally means that the store was not 
     * initialized properly.
     * 
     * @return the integrity object, or null if no object can be retrieved.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     */
    IntegrityData getIntegrityData() throws KeyStoreDAOException;
    
    /**
     * Assign an {@code IntegrityData} object to this object.
     * This method may be called in initialization methods of the key store or key manager factory objects, when the 
     * structure needs to be created.
     * 
     * @param integrityData the IntegrityData object.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     * @see com.vaderetrosecure.keystore.VRKeyStoreSpi#engineLoad(java.io.InputStream, char[])
     * @see com.vaderetrosecure.ssl.VRKeyManagerFactorySpi#engineInit(KeyStore, char[])
     */
    void setIntegrityData(IntegrityData integrityData) throws KeyStoreDAOException;
    
    /**
     * Return the {@code KeyStoreEntry} object matching the alias given in parameter.
     * Only one {@code KeyStoreEntry} object can match with an alias. 
     * 
     * @param alias the alias the KeyStoreEntry object must match with.
     * @return a KeyStoreEntry object, or null if not found.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     */
    KeyStoreEntry getEntry(String alias) throws KeyStoreDAOException;
    
    /**
     * Return each entry that its associated names list matches the name in parameter.
     * This method is used by the {@code TLSSSLContextSpi} object when performing SNI matching. 
     * 
     * @param name the name entries must match with.
     * @return the list of entries matching the name, or an empty list if not match was found.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     * @see com.vaderetrosecure.ssl.TLSSSLContextSpi
     * @see javax.net.ssl.SNIMatcher
     */
    List<KeyStoreEntry> getEntries(String name) throws KeyStoreDAOException;
    
    /**
     * Add an entry to the store.
     * If an entry already exists, it is replaced, whatever the type of entry.
     * 
     * @param entry the entry to store.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     */
    void setEntry(KeyStoreEntry entry) throws KeyStoreDAOException;
    
    /**
     * Remove a {@code KeyStoreEntry} object from the underlying store.
     * This method removes all data associated with the alias, including the 
     * certificate chain and list of names of this entry if any.
     * 
     * @param entry the object to delete.
     * @throws KeyStoreDAOException if the implementation can not process because of an underlying error.
     */
    void deleteEntry(KeyStoreEntry entry) throws KeyStoreDAOException;
}
