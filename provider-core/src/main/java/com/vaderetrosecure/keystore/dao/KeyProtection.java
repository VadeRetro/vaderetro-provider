/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

/**
 * This class is used to protect secret and private keys of the key store. 
 * It contains an AES secret key with its initialization vector.<br>
 * <b>Be aware</b> that objects from this class are used by {@link com.vaderetrosecure.keystore.VRKeyStoreSpi} to
 * create protections but are never stored. Implementors must only store {@link LockedKeyProtection} objects that, 
 * internally, will be derived to create {@code KeyProtection} objects. 
 * 
 * @author ahonore
 * @see com.vaderetrosecure.keystore.VRKeyStoreSpi
 * @see com.vaderetrosecure.keystore.dao.LockedKeyProtection
 */
public class KeyProtection
{
    private static final Logger LOG = Logger.getLogger(KeyProtection.class);

    private SecretKey key;
    private byte[] iv;
    
    /**
     * Construct a new empty {@code KeyProtection}. 
     */
    public KeyProtection()
    {
        this(null, new byte[]{});
    }
    
    /**
     * Construct a new {@code KeyProtection}, given a secret key and a 
     * initialization vector.
     * 
     * @param key the secret key.
     * @param iv the initialization vector.
     * @see javax.crypto.SecretKey
     */
    public KeyProtection(SecretKey key, byte[] iv)
    {
        this.key = key;
        this.iv = iv;
    }
    
    /**
     * Construct a new {@code KeyProtection}, from a {@code LockedKeyProtection} object.
     * If the {@code VRKeyStoreSpi} locked it with public key, a private key must be
     * given to decipher it.
     * 
     * @param lockedKeyProtection the LockedKeyProtection object that can be stored.
     * @param privateKey if the LockedKeyProtection object was ciphered by the VRKeyStoreSpi, it is mandatory. Otherwise, it is set to null.
     * @throws InvalidKeyException if the private key is wrong.
     * @throws NoSuchAlgorithmException if algorithm was not found.
     * @throws NoSuchPaddingException if key can not be deciphered.
     * @throws IllegalBlockSizeException if key can not be deciphered.
     * @throws BadPaddingException if key can not be deciphered.
     * @see com.vaderetrosecure.keystore.dao.LockedKeyProtection
     */
    public KeyProtection(LockedKeyProtection lockedKeyProtection, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        this.key = unlockCipheredKey(lockedKeyProtection.getCipheredKey(), privateKey);
        this.iv = lockedKeyProtection.getIV();
    }

    /**
     * Give the secret key used to decipher stored secret and private keys.
     * 
     * @return the secret key.
     */
    public SecretKey getKey()
    {
        return key;
    }

    /**
     * Assign a secret key to this object.
     * 
     * @param key the secret key.
     */
    public void setKey(SecretKey key)
    {
        this.key = key;
    }

    /**
     * Give the initialization vector used with the secret key.
     * 
     * @return the initialization vector.
     */
    public byte[] getIV()
    {
        return iv;
    }

    /**
     * Assign an initialization vector to this object.
     * 
     * @param iv the initialization vector.
     */
    public void setIV(byte[] iv)
    {
        this.iv = iv;
    }
    
    /**
     * Generate a {@code KeyProtection} object, given a password and salt.
     * Password and salt are used to generate the secret key. An initialization vector
     * is also generated using a strong random number generator.<b>This method is the 
     * preferred way</b> to generate a new {@code KeyProtection} object.<br>
     * Implementors do not need to call this method.
     * 
     * @param password the password to protect the stored key. 
     * @param salt salt used with the password to generate the KeyProtection object.
     * @return an new KeyProtection object.
     * @throws NoSuchAlgorithmException if algorithm was not found.
     * @throws InvalidKeySpecException if the IV is malformed.
     */
    public static KeyProtection generateKeyProtection(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] iv = CryptoTools.generateIV();
        return generateKeyProtection(password, salt, iv);
    }
    
    /**
     * Generate a {@code KeyProtection} object, given a password, salt and an initialization vector.
     * Password and salt are used to generate the secret key. An initialization vector
     * is also generated using a strong random number generator.<br>
     * Implementors do not need to call this method.
     * 
     * @param password the password to protect the stored key.
     * @param salt salt used with the password to generate the KeyProtection object.
     * @param iv an initialization vector.
     * @return an new KeyProtection object.
     * @throws NoSuchAlgorithmException if algorithm was not found.
     * @throws InvalidKeySpecException if the IV is malformed.
     */
    public static KeyProtection generateKeyProtection(char[] password, byte[] salt, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKey sk = CryptoTools.getAESSecretKey(password, salt);
        return new KeyProtection(sk, iv);
    }
    
    private SecretKey unlockCipheredKey(byte[] cipheredKey, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        SecretKey sk = null;
        if (privateKey == null)
        {
            LOG.debug("No public key, now try to unlock a readable key protection");
            sk = new SecretKeySpec(cipheredKey, "AES");
        }
        else
            sk = new SecretKeySpec(CryptoTools.decipherData(cipheredKey, privateKey), "AES");
        
        return sk;
    }

    /**
     * Create a {@code LockedKeyProtection} object from this {@code KeyProtection} object.
     * A public key can be given in parameter to cipher this object. This method is called by 
     * {@code VRKeyStoreSpi} to create a ciphered key protection that can be stored.<br>
     * <b>Be aware that not using a public key implies a security vulnerability</b>, because a third party program can potentially decipher
     * all stored keys, if the storage entity is attainable.
     * Implementors do not need to call this method.
     * 
     * @param publicKey the public key used to cipher this object. May be null if not required, but implies a security vulnerability.
     * @return a new LockedKeyProtection object.
     * @throws InvalidKeyException if the public key is not valid.
     * @throws NoSuchAlgorithmException if algorithm is not found.
     * @throws NoSuchPaddingException if the public key is wrong or not large enough.
     * @throws IllegalBlockSizeException if the public key is wrong or not large enough.
     * @throws BadPaddingException if the public key is wrong or not large enough.
     * @see com.vaderetrosecure.keystore.dao.LockedKeyProtection
     * @see com.vaderetrosecure.keystore.VRKeyStoreSpi
     */
    public LockedKeyProtection getLockedKeyProtection(PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
    {
        LockedKeyProtection lkp = null;
        if (publicKey == null)
        {
            LOG.debug("No private key, so key protection will be readable");
            lkp = new LockedKeyProtection(getKey().getEncoded(), getIV());
        }
        else
            lkp = new LockedKeyProtection(CryptoTools.cipherData(getKey().getEncoded(), publicKey), getIV());
        
        return lkp;
    }
}
