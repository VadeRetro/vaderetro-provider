/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

/**
 * The type of {@link com.vaderetrosecure.keystore.dao.KeyStoreEntry} object that is actually stored.
 */
public enum KeyStoreEntryType
{
    /**
     * The entry is a secret key, i.e. a symmetric algorithm key.
     */
    SECRET_KEY,
    
    /**
     * The entry is a private key, .i.e. an asymmetric algorithm private key.
     * A certificate chain may be attached to this entry.
     */
    PRIVATE_KEY,
    
    /**
     * A certificate, used as an authority for others.
     */
    TRUSTED_CERTIFICATE
}
