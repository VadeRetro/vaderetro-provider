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
    int countEntries();
    List<String> getAliases();
    byte[] getKey(String alias);
    Certificate getCertificate(String alias);
    Certificate[] getCertificateChain(String alias);
    Date engineGetCreationDate(String alias);
    
    boolean isCertificateEntry(String alias);
    boolean isKeyEntry(String alias);
    
    void setKeyEntry(String alias, byte[] key, Certificate[] chain);
    
    void deleteEntry(String alias);
}
