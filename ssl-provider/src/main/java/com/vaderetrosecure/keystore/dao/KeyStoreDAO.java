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
    
    IntegrityData getIntegrityData() throws KeyStoreDAOException;
    
    int countEntries() throws KeyStoreDAOException;
    
    List<String> getAliases() throws KeyStoreDAOException;
    
    /**
     * Get aliases that refer to private key/certificate pairs.
     * It is useful for server authentication.
     * 
     * @param keyType the algorithm name used to create the key and certificate pair (i.e.: EC_EC, RSA, DSA...).
     * @return
     * @throws KeyStoreDAOException
     */
    List<String> getAuthenticationAliases(String keyType) throws KeyStoreDAOException;
    
    KeyEntry getKeyEntry(String alias) throws KeyStoreDAOException;
    
    CertificateEntry getCertificate(String name) throws KeyStoreDAOException;
    
    /**
     * Return the certificate chain given by the name of the first certificate.
     * 
     * @param name the alias or one of the names of the certificate.
     * @return
     * @throws KeyStoreDAOException
     */
    List<CertificateEntry> getCertificateChain(String name) throws KeyStoreDAOException;
    
    /**
     * Return the date of the creation of the entry in the structure.
     * 
     * @param alias
     * @return
     * @throws KeyStoreDAOException
     */
    DateEntry getDateEntry(String alias) throws KeyStoreDAOException;
    
    void setDateEntry(String alias) throws KeyStoreDAOException;
    
    void setIntegrityData(IntegrityData integrityData) throws KeyStoreDAOException;
    
    void setEntry(KeyEntry keyEntry, List<CertificateEntry> certificateEntries) throws KeyStoreDAOException;

    void setCertificateEntry(CertificateEntry certificateEntry) throws KeyStoreDAOException;

    void deleteKeyEntry(String alias) throws KeyStoreDAOException;

    void deleteCertificateEntry(String alias) throws KeyStoreDAOException;
}
