/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

/**
 * @author ahonore
 *
 */
public interface VRKeyStoreDAO
{
    void checkSchema();
    
    KeyStoreMetaData getMetaData();
    
    int countEntries();
    List<String> getAliases();
    byte[] getKey(String alias);
    Certificate getCertificate(String alias);
    List<Certificate> getCertificateChain(String alias);
    Date engineGetCreationDate(String alias);
    
    boolean isCertificateEntry(String alias);
    boolean isKeyEntry(String alias);
    
    void setKey(String alias, byte[] key);
    void setCertificate(String alias, Certificate certificate);
    void setCertificateChain(String alias, Certificate[] certificateChain);
    
    void deleteEntry(String alias);
}
