/**
 * 
 */
package com.vaderetrosecure.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.IntegrityData;
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
        List<Certificate> certChain = keystoreDAO.getCertificateChain(alias);
        if (certChain.isEmpty())
            return null;
        
        return certChain.toArray(new Certificate[]{});
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        // TODO Auto-generated method stub
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
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public int engineSize()
    {
        // TODO Auto-generated method stub
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
        LOG.warn("engineStore: does nothing");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (!checkKeyStoreDAOIsLoaded())
        {
            final String errorMsg = "keystore dao is not loaded";
            LOG.fatal(errorMsg);
            throw new IOException(errorMsg);
        }
        
        IntegrityData integrityData = keystoreDAO.getIntegrityData();
        integrityData.checkIntegrity();
    }

    
    private boolean checkKeyStoreDAOIsLoaded()
    {
        return keystoreDAO != null;
    }
}
