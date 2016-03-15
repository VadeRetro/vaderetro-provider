/**
 * 
 */
package com.vaderetrosecure.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaData;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAO;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.VRKeyStoreDAOFactory;

/**
 * @author ahonore
 *
 */
public class VRKeystoreSpi extends KeyStoreSpi
{
    private final static Logger LOG = Logger.getLogger(VRKeystoreSpi.class);

    private VRKeyStoreDAO keystoreDAO;
    private Cipher masterCipher;
    private Cipher masterDecipher;
    
    public VRKeystoreSpi()
    {
        keystoreDAO = null;
        masterCipher = null;
        masterDecipher = null;
        try
        {
            VRKeyStoreDAOFactory ksFactory = VRKeyStoreDAOFactory.getInstance();
            keystoreDAO = ksFactory.getKeyStoreDAO();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.fatal(e, e);
        }
    }
    
    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            return null;
        }

        List<Certificate> certChain = getListOfCertificates(alias);
        if (certChain.isEmpty())
            return null;
        
        return certChain.toArray(new Certificate[]{});
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            return null;
        }

        List<Certificate> certChain = getListOfCertificates(alias);
        if (certChain.isEmpty())
            return null;
        
        return certChain.get(0);
    }

    private List<Certificate> getListOfCertificates(String alias)
    {
        try
        {
            List<KeyStoreEntry> entries = keystoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE);
            if (entries.isEmpty())
                return Collections.emptyList();
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<Certificate> certChain = new ArrayList<>();
            for (KeyStoreEntry kse : entries)
            {
                try (InputStream is = new ByteArrayInputStream(kse.getData()))
                {
                    Certificate cert = cf.generateCertificate(is);
                    certChain.add(cert);
                }
                catch (IOException e)
                {
                    LOG.error(e, e);
                }
            }
            
            return certChain;
        }
        catch (VRKeyStoreDAOException | CertificateException e)
        {
            LOG.error(e, e);
        }
        
        return Collections.emptyList();
    }
    
    @Override
    public Date engineGetCreationDate(String alias)
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            return null;
        }

        try
        {
            List<KeyStoreEntry> entries = keystoreDAO.getKeyStoreEntry(alias);
            if (entries.isEmpty())
                return null;
            
            return entries.get(0).getCreationDate();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }
        
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException
    {
        // TODO Auto-generated method stub
        
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            return Collections.emptyEnumeration();
        }

        try
        {
            List<String> aliases = keystoreDAO.getAliases();
            if (aliases.isEmpty())
                return Collections.emptyEnumeration();
            
            return Collections.enumeration(aliases);
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }

        return Collections.emptyEnumeration();
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            return false;
        }

        try
        {
            return !keystoreDAO.getKeyStoreEntry(alias).isEmpty();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }

        return false;
    }

    @Override
    public int engineSize()
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            return 0;
        }

        try
        {
            return keystoreDAO.countEntries();
        }
        catch (VRKeyStoreDAOException e)
        {
            LOG.error(e, e);
        }

        return 0;
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        LOG.warn("engineGetCertificateAlias: not yet implemented");
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            throw new IOException();
        }
        
        try
        {
            keystoreDAO.checkSchema();
            KeyStoreMetaData ksmd = KeyStoreMetaData.generate(password);
            keystoreDAO.setMetaData(ksmd);
        }
        catch (VRKeyStoreDAOException | UnrecoverableKeyException e)
        {
            LOG.error(e, e);
            throw new IOException(e);
        }
        catch (GeneralSecurityException e)
        {
            LOG.error(e, e);
            throw new NoSuchAlgorithmException(e);
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            throw new IOException();
        }
        
        try
        {
            KeyStoreMetaData ksmd = keystoreDAO.getMetaData();
            ksmd.checkIntegrity(password);
        }
        catch (VRKeyStoreDAOException | GeneralSecurityException e)
        {
            LOG.error(e);
            throw new IOException(e);
        }
    }

    
    private void checkKeyStoreDAOIsLoaded() throws IOException
    {
        if (keystoreDAO != null)
        {
            final String errorMsg = "keystore dao is not loaded";
            LOG.fatal(errorMsg);
            throw new IOException(errorMsg);
        }
    }
}
