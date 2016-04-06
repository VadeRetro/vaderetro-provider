/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.IOException;
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
 * @author ahonore
 *
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

    protected KeyStoreEntry()
    {
        this("", Date.from(Instant.now()), KeyStoreEntryType.TRUSTED_CERTIFICATE, null, new byte[]{}, null, Collections.emptyList(), Collections.emptyList());
    }

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

    public KeyStoreEntry(String alias, Date creationDate, Key key, KeyProtection keyProtection, List<CertificateData> certificateChain, List<String> names) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        this(alias, creationDate, (PrivateKey.class.isInstance(key)) ? KeyStoreEntryType.PRIVATE_KEY : KeyStoreEntryType.SECRET_KEY, key, keyProtection, Collections.emptyList(), Collections.emptyList());
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
    
    public String getAlias()
    {
        return alias;
    }

    public void setAlias(String alias)
    {
        this.alias = alias;
    }

    public Date getCreationDate()
    {
        return creationDate;
    }

    public void setCreationDate(Date creationDate)
    {
        this.creationDate = creationDate;
    }

    public KeyStoreEntryType getEntryType()
    {
        return entryType;
    }

    public void setEntryType(KeyStoreEntryType entryType)
    {
        this.entryType = entryType;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public byte[] getEntryData()
    {
        return entryData;
    }

    public void setEntryData(byte[] entryData)
    {
        this.entryData = entryData;
    }

    public LockedKeyProtection getLockedKeyProtection()
    {
        return lockedKeyProtection;
    }

    public void setLockedKeyProtection(LockedKeyProtection lockedKeyProtection)
    {
        this.lockedKeyProtection = lockedKeyProtection;
    }

    public List<CertificateData> getCertificateChain()
    {
        return certificateChain;
    }

    public void setCertificateChain(List<CertificateData> certificateChain)
    {
        this.certificateChain = certificateChain;
    }

    public List<String> getNames()
    {
        return names;
    }

    public void setNames(List<String> names)
    {
        this.names = names;
    }
    
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

    public void setKey(Key key, KeyProtection keyProtection) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        setEntryData(CryptoTools.cipherData(key.getEncoded(), keyProtection.getKey(), keyProtection.getIV()));
    }

    public Certificate getTrustedCertificate() throws IOException, CertificateException
    {
        return CryptoTools.decodeCertificate(getEntryData());
    }
}
