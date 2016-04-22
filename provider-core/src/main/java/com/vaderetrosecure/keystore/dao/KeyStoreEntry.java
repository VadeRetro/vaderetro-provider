/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class represents a entry in the key store.
 * This is the main class an implementors must deal with to provide a {@code KeyStoreDAO}. Each instance represents one of the following entry:
 * <ul>
 * <li>a secret key, if {@code getEntryType() == KeyStoreEntryType.SECRET_KEY}</li>
 * <li>a trusted certificate, if {@code getEntryType() == KeyStoreEntryType.TRUSTED_CERTIFICATE}</li>
 * <li>a private key, if {@code getEntryType() == KeyStoreEntryType.PRIVATE_KEY}, eventually associated with a certificate chain and certificate names.</li>
 * </ul>
 * Here, certificate names are used by the SSL context to perform SNI matching.
 * 
 * @author ahonore
 * @see com.vaderetrosecure.keystore.dao.KeyStoreDAO
 */
public class KeyStoreEntry
{
    private String alias;
    private Date creationDate;
    private KeyStoreEntryType entryType;
    private String algorithm;
    private byte[] entryData;
    private LockedKeyProtection lockedKeyProtection;
    private List<CertificateData> certificateChain;
    private List<String> names;

    /**
     * Construct a default {@code KeyStoreEntry} object.
     */
    protected KeyStoreEntry()
    {
        this("", Date.from(Instant.now()), KeyStoreEntryType.TRUSTED_CERTIFICATE, null, new byte[]{}, null, Collections.emptyList(), Collections.emptyList());
    }

    /**
     * Construct a new {@code KeyStoreEntry} object.
     * 
     * @param alias the alias associated with this entry.
     * @param creationDate the date the entry was created.
     * @param entryType the type of entry.
     * @param algorithm the algorithm of the key (i.e. RSA, DSA...)
     * @param entryData the entry as an array of bytes.
     * @param lockedKeyProtection the protection used to cipher the {@code entryData}.
     * @param certificateChain the certificate chain in case of a private key, empty otherwise.
     * @param names names extracted from the first certificate, empty if no certificate chain is associated.
     */
    public KeyStoreEntry(String alias, Date creationDate, KeyStoreEntryType entryType, String algorithm, byte[] entryData, LockedKeyProtection lockedKeyProtection, List<CertificateData> certificateChain, List<String> names)
    {
        this.alias = alias;
        this.creationDate = creationDate;
        this.entryType = entryType;
        this.algorithm = algorithm;
        this.entryData = entryData;
        this.lockedKeyProtection = lockedKeyProtection;
        this.certificateChain = certificateChain;
        this.names = names;
    }
    
    /**
     * Construct a new {@code KeyStoreEntry} object, containing a trusted certificate.
     * 
     * @param alias the alias associated with this entry.
     * @param creationDate the date the entry was created.
     * @param trustedCertificate the trsuted certificate.
     * @throws CertificateEncodingException if the certificate can not be extracted as bytes.
     */
    public KeyStoreEntry(String alias, Date creationDate, Certificate trustedCertificate) throws CertificateEncodingException
    {
        this.alias = alias;
        this.creationDate = creationDate;
        this.entryType = KeyStoreEntryType.TRUSTED_CERTIFICATE;
        this.algorithm = null;
        this.entryData = trustedCertificate.getEncoded();
        this.lockedKeyProtection = null;
        this.certificateChain = Collections.emptyList();
        this.names = Collections.emptyList();
    }

    /**
     * Construct a new {@code KeyStoreEntry} object, containing a secret or a private key.
     * 
     * @param alias the alias associated with this entry.
     * @param creationDate the date the entry was created.
     * @param key the secret or private key.
     * @param keyProtection the KeyProtection object used to protect the key.
     * @param certificateChain the certificate chain if the entry is a private key, empty otherwise.
     * @param names names extracted from the first certificate, empty if no certificate chain is associated.
     * @throws InvalidKeyException if the KeyProtection object key is wrong.
     * @throws NoSuchAlgorithmException if the protection algorithm is not found.
     * @throws InvalidKeySpecException if the KeyProtection object uses a bad parameter.
     * @throws NoSuchPaddingException if the KeyProtection object key is wrong.
     * @throws InvalidAlgorithmParameterException if the KeyProtection object uses a bad parameter.
     * @throws IllegalBlockSizeException if the KeyProtection object key is wrong.
     * @throws BadPaddingException if the KeyProtection object key is wrong.
     */
    public KeyStoreEntry(String alias, Date creationDate, Key key, KeyProtection keyProtection, List<CertificateData> certificateChain, List<String> names) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        this(alias, creationDate, PrivateKey.class.isInstance(key) ? KeyStoreEntryType.PRIVATE_KEY : KeyStoreEntryType.SECRET_KEY, key, keyProtection, certificateChain, names);
    }

    protected KeyStoreEntry(String alias, Date creationDate, KeyStoreEntryType entryType, Key key, KeyProtection keyProtection, List<CertificateData> certificateChain, List<String> names) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        this.alias = alias;
        this.creationDate = creationDate;
        this.entryType = entryType;
        this.algorithm = key.getAlgorithm();
        setKey(key, keyProtection);
        this.lockedKeyProtection = null;
        this.certificateChain = certificateChain;
        this.names = names;
    }
    
    /**
     * Give the alias associated with this entry.
     * 
     * @return the alias.
     */
    public String getAlias()
    {
        return alias;
    }

    /**
     * Assign an alias to this object.
     * 
     * @param alias the alias.
     */
    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    /**
     * Give the date the entry was created.
     * 
     * @return the date.
     */
    public Date getCreationDate()
    {
        return creationDate;
    }

    /**
     * Assign the date the entry was created to this object.
     * 
     * @param creationDate the date.
     */
    public void setCreationDate(Date creationDate)
    {
        this.creationDate = creationDate;
    }

    /**
     * Give the type of entry.
     * 
     * @return the type of entry.
     * @see com.vaderetrosecure.keystore.dao.KeyStoreEntryType
     */
    public KeyStoreEntryType getEntryType()
    {
        return entryType;
    }

    /**
     * Assign a type of entry to this object.
     * This method is called at object construction.
     * 
     * @param entryType the type of entry.
     */
    public void setEntryType(KeyStoreEntryType entryType)
    {
        this.entryType = entryType;
    }

    /**
     * Give the name of the algorithm of this entry.
     * 
     * @return the name of the algorithm.
     */
    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Give the name of the algorithm of this entry.
     * 
     * @param algorithm the name of the algorithm.
     */
    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    /**
     * Return the entry data.
     * The entry is a raw entry and must be decoded using the {@code getKey()} or {@code getTrustedCertificate()} method.
     * 
     * @return the entry data as an array of bytes.
     * @see #getKey(KeyProtection)
     * @see #getTrustedCertificate()
     */
    public byte[] getEntryData()
    {
        return entryData;
    }

    /**
     * Assign entry data to this object.
     * This method is called by constructors when ciphering keys or encoding trusted certificates.
     * 
     * @param entryData an array of bytes as entry data.
     */
    public void setEntryData(byte[] entryData)
    {
        this.entryData = entryData;
    }

    /**
     * Return the {@code LockedKeyProtection} object used to protect the key.
     * 
     * @return the LockedKeyProtection object, or null if the entry is a trusted certificate.
     */
    public LockedKeyProtection getLockedKeyProtection()
    {
        return lockedKeyProtection;
    }

    /**
     * Assign a {@code LockedKeyProtection} object to this object.
     * It can be set to {@code null} if the entry is a trusted certificate.
     * 
     * @param lockedKeyProtection a {@code LockedKeyProtection} object.
     */
    public void setLockedKeyProtection(LockedKeyProtection lockedKeyProtection)
    {
        this.lockedKeyProtection = lockedKeyProtection;
    }

    /**
     * Give the certificate chain.
     * It can be an empty list if the entry is:
     * <ul>
     * <li>a secret key</li>
     * <li>a private key.</li>
     * </ul>
     * The list is ordered from the certificate associated to the private key to the certificate of the global authority.
     * 
     * @return the certificate chain.
     */
    public List<CertificateData> getCertificateChain()
    {
        return certificateChain;
    }

    /**
     * Assign a certificate chain to this object.
     * 
     * @param certificateChain a certificate chain, or an empty list.
     */
    public void setCertificateChain(List<CertificateData> certificateChain)
    {
        this.certificateChain = certificateChain;
    }

    /**
     * Give the names associated to the first certificate of the chain.
     * Names are extracted from the {@code CN} and {@code Subject Alt dNS} names.
     * It can be an empty list if the entry is:
     * <ul>
     * <li>a secret key</li>
     * <li>a trusted certificate.</li>
     * </ul>
     * 
     * @return the list of names associated to the certificate chain.
     */
    public List<String> getNames()
    {
        return names;
    }

    /**
     * Assign a list of names to this object.
     * 
     * @param names the list of names.
     */
    public void setNames(List<String> names)
    {
        this.names = names;
    }
    
    /**
     * Return the key represented by this object.
     * It can be:
     * <ul>
     * <li>a secret key, if {@code getEntryType() == KeyStoreEntryType.SECRET_KEY}</li>
     * <li>a private key, if {@code getEntryType() == KeyStoreEntryType.PRIVATE_KEY}.</li>
     * </ul>
     * 
     * @param keyProtection the key protection to decipher entry data.
     * @return the key, or null if the entry is not a key.
     * @throws InvalidKeyException if the KeyProtection object is wrong.
     * @throws NoSuchAlgorithmException if the algorithm can not be found.
     * @throws InvalidKeySpecException if the KeyProtection object is wrong.
     * @throws NoSuchPaddingException if the algorithm is wrong.
     * @throws InvalidAlgorithmParameterException if the KeyProtection object is wrong.
     * @throws IllegalBlockSizeException if entry data are wrong.
     * @throws BadPaddingException if entry data are wrong.
     */
    public Key getKey(KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] encKey = CryptoTools.decipherData(getEntryData(), keyProtection.getKey(), keyProtection.getIV());

        Key k = null;
        switch (getEntryType())
        {
        case SECRET_KEY:
            k = new SecretKeySpec(encKey, getAlgorithm());
            break;
        case PRIVATE_KEY:
            KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
            k = kf.generatePrivate(new PKCS8EncodedKeySpec(encKey));
            break;
        default:
        }
        return k;
    }

    /**
     * Assign a key to this object.
     * The key is ciphered using the {@code KeyProtection} object given in parameter.
     * 
     * @param key the key.
     * @param keyProtection the KeyProtection object to cipher the key.
     * @throws InvalidKeyException if the KeyProtection object is wrong.
     * @throws NoSuchAlgorithmException if the ciphering algorithm can not be found.
     * @throws InvalidKeySpecException if the KeyProtection object is wrong.
     * @throws NoSuchPaddingException if the key can not be ciphered.
     * @throws InvalidAlgorithmParameterException if the ciphering algorithm is wrong.
     * @throws IllegalBlockSizeException if the key can not be ciphered.
     * @throws BadPaddingException if the key can not be ciphered.
     */
    public void setKey(Key key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setEntryData(CryptoTools.cipherData(key.getEncoded(), keyProtection.getKey(), keyProtection.getIV()));
    }

    /**
     * Return the entry as a trusted certificate.
     * 
     * @return the certificate.
     * @throws CertificateException if entry data are not representing a certificate.
     */
    public Certificate getTrustedCertificate() throws CertificateException
    {
        return CryptoTools.decodeCertificate(getEntryData());
    }
}
