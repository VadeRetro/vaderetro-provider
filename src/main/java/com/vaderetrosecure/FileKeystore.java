/**
 * 
 */
package com.vaderetrosecure;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import com.google.common.base.Joiner;

/**
 * @author ahonore
 *
 */
public class FileKeystore extends KeyStoreSpi
{
    private static final Logger LOG = Logger.getLogger(FileKeystore.class);
    
//    private static final String SECURITY_PROVIDER = "BC";
//    static
//    {
//        Security.addProvider(new BouncyCastleProvider());
//    }

    private static final String[] hosts = new String[] { "machin.fr", "pouet.fr" };
    
    private Map<String, KeyStoreEntry> aliasKeyStoreEntryMap;
    
    public FileKeystore()
    {
        aliasKeyStoreEntryMap = new HashMap<>();
        for (String h : hosts)
            aliasKeyStoreEntryMap.put(h, loadEntryFromFile(h));
    }
    
    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        LOG.debug("engineGetKey: " + alias);
        KeyStoreEntry kse = getEntry(alias);
        if (kse != null)
            return kse.key;
        
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        LOG.debug("engineGetCertificateChain: " + alias);
//        KeyStoreEntry kse = getEntry(alias);
//        if (kse != null)
//            return kse.certificate;
        
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        LOG.debug("engineGetCertificate: " + alias);
        KeyStoreEntry kse = getEntry(alias);
        if (kse != null)
        {
            LOG.debug(kse.certificate.toString());
            return kse.certificate;
        }
        
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        LOG.debug("engineGetCreationDate: " + alias);
        KeyStoreEntry kse = aliasKeyStoreEntryMap.get(alias);
        if (kse != null)
        {
            LOG.debug(kse.date);
            return kse.date;
        }
        
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException
    {
        LOG.info("engineSetKeyEntry not implemented: read only");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException
    {
        LOG.info("engineSetKeyEntry not implemented: read only");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException
    {
        LOG.info("engineSetCertificateEntry not implemented: read only");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException
    {
        LOG.info("engineDeleteEntry not implemented: read only");
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        LOG.debug("engineAliases: " + Joiner.on(",").join(aliasKeyStoreEntryMap.keySet()));
        return Collections.enumeration(aliasKeyStoreEntryMap.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        LOG.debug("engineContainsAlias: " + alias);
        return getEntry(alias) != null;
    }

    @Override
    public int engineSize()
    {
        LOG.debug("engineSize: " + Integer.toString(aliasKeyStoreEntryMap.size()));
        return aliasKeyStoreEntryMap.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        LOG.debug("engineIsKeyEntry: " + alias);
        KeyStoreEntry kse = getEntry(alias);
        return kse != null;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        LOG.debug("engineIsCertificateEntry: " + alias);
        KeyStoreEntry kse = getEntry(alias);
        return kse != null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        LOG.debug("engineGetCertificateAlias: " + cert);
        for (Map.Entry<String, KeyStoreEntry> entry : aliasKeyStoreEntryMap.entrySet())
            if (entry.getValue().certificate.equals(cert))
            {
                LOG.debug("engineGetCertificateAlias: key = " + entry.getKey());
                return entry.getKey();
            }
        
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        LOG.info("engineStore not implemented: read only");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        LOG.info("engineStore not implemented");
    }

    private KeyStoreEntry getEntry(String alias)
    {
        LOG.debug("getEntry: " + alias);
        if (!aliasKeyStoreEntryMap.containsKey(alias))
        {
            KeyStoreEntry kse = loadEntryFromFile(alias);
            if (kse != null)
                aliasKeyStoreEntryMap.put(alias, kse);
        }
        
        LOG.debug("getEntry: " + aliasKeyStoreEntryMap.get(alias).certificate);
        return aliasKeyStoreEntryMap.get(alias);
    }
    
    private KeyStoreEntry loadEntryFromFile(String alias)
    {
        LOG.debug("loadEntryFromFile: " + alias);
//        File fkey = new File(alias + ".key");
//        File fcert = new File(alias + ".crt");
        File fkey = new File(alias + ".key.der");
        File fcert = new File(alias + ".crt.der");
        
        if (!fkey.exists() || !fcert.exists())
            return null;
        
        try
        {
            Certificate cert = null;
            Key k = null;
//            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", SECURITY_PROVIDER);
//            try (FileInputStream fis = new FileInputStream(fcert))
//            {
//                cert = certFactory.generateCertificate(fis);
//            }
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            try (FileInputStream fis = new FileInputStream(fcert))
            {
                cert = certFactory.generateCertificate(fis);
            }

            LOG.debug("found cert: " + cert);

//            try (PEMParser pr = new PEMParser(new FileReader(fkey)))
//            {
//                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(SECURITY_PROVIDER);
//                k = converter.getPrivateKey((PrivateKeyInfo) pr.readObject());
//            }
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            try (DataInputStream dis = new DataInputStream(new FileInputStream(fkey)))
            {
                byte[] privKeyBytes = new byte[(int)fkey.length()];
                dis.read(privKeyBytes);
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
                k = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
            }

            LOG.debug("found private key: " + k);

            return new KeyStoreEntry(new Date(), k, cert);
        }
        catch (CertificateException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            LOG.warn(e, e);
        }
        
        return null;
    }
    
    private static class KeyStoreEntry
    {
        public Date date;
        public Key key;
        public Certificate certificate;
        
        public KeyStoreEntry(Date date, Key key, Certificate certificate)
        {
            this.date = date;
            this.key = key;
            this.certificate = certificate;
        }
    }
}
