/**
 * 
 */
package com.vaderetrosecure.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.log4j.Logger;

import com.vaderetrosecure.keystore.dao.CertificateData;
import com.vaderetrosecure.keystore.dao.IntegrityData;
import com.vaderetrosecure.keystore.dao.KeyProtection;
import com.vaderetrosecure.keystore.dao.KeyStoreDAO;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOException;
import com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory;
import com.vaderetrosecure.keystore.dao.KeyStoreEntry;
import com.vaderetrosecure.keystore.dao.KeyStoreEntryType;
import com.vaderetrosecure.keystore.dao.LockedKeyProtection;

/**
 * @author ahonore
 *
 *         private/public key pair size for key protection must be at least
 *         2048.
 */
public class VRKeyStoreSpi extends KeyStoreSpi
{
    private static final Logger LOG = Logger.getLogger(VRKeyStoreSpi.class);

    private static final String VR_KEYSTORE_PUBLIC_KEY_FILE = "com.vaderetrosecure.key.public";

    private KeyStoreDAO keystoreDAO;
    private PublicKey publicKey;

    public VRKeyStoreSpi()
    {
        keystoreDAO = null;
        publicKey = null;

        try
        {
            KeyStoreDAOFactory ksFactory = KeyStoreDAOFactory.getInstance();
            keystoreDAO = ksFactory.getKeyStoreDAO();
        }
        catch (KeyStoreDAOException e)
        {
            LOG.fatal(e, e);
        }
    }

    VRKeyStoreSpi(KeyStoreDAO keystoreDAO)
    {
        this.keystoreDAO = keystoreDAO;
        this.publicKey = null;
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            if (kse == null)
                return null;

            switch (kse.getEntryType())
            {
            case SECRET_KEY:
            case PRIVATE_KEY:
                break;
            default:
                return null;
            }

            IntegrityData id = keystoreDAO.getIntegrityData();
            if (id == null)
            {
                final String msg = "IntegrityData not found";
                LOG.error(msg);
                throw new UnrecoverableKeyException(msg);
            }

            LockedKeyProtection lkp = kse.getLockedKeyProtection();
            if (lkp == null)
            {
                final String msg = "KeyProtection not found";
                LOG.error(msg);
                throw new UnrecoverableKeyException(msg);
            }

            KeyProtection kp = KeyProtection.generateKeyProtection(password, id.getSalt(), lkp.getIV());

            return kse.getKey(kp);
        }
        catch (IOException | KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }
        catch (InvalidKeySpecException | NoSuchAlgorithmException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new NoSuchAlgorithmException(e);
        }
        catch (InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new UnrecoverableKeyException("wrong key password");
        }

        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            if ((kse == null) || (kse.getEntryType() != KeyStoreEntryType.PRIVATE_KEY))
                return null;

            List<CertificateData> certChain = kse.getCertificateChain();
            if (!certChain.isEmpty())
            {
                List<Certificate> certs = new ArrayList<>();
                for (CertificateData ce : certChain)
                    certs.add(ce.getCertificate());

                return certs.toArray(new Certificate[] {});
            }
        }
        catch (CertificateException | KeyStoreDAOException | IOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }

        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            if (kse == null)
                return null;

            Certificate c = null;
            switch (kse.getEntryType())
            {
            case PRIVATE_KEY:
                List<CertificateData> certChain = kse.getCertificateChain();
                if (!certChain.isEmpty())
                    c = certChain.get(0).getCertificate();
                break;
            case TRUSTED_CERTIFICATE:
                c = kse.getTrustedCertificate();
                break;
            default:
                break;
            }

            return c;
        }
        catch (CertificateException | KeyStoreDAOException | IOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }

        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            if (kse != null)
                return kse.getCreationDate();
        }
        catch (KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }
        catch (IOException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
        }

        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            IntegrityData id = keystoreDAO.getIntegrityData();
            if (id == null)
            {
                final String msg = "IntegrityData not found";
                LOG.error(msg);
                throw new KeyStoreException(msg);
            }

            Date creationDate = Date.from(Instant.now());

            KeyProtection kp = KeyProtection.generateKeyProtection(password, id.getSalt());

            List<CertificateData> certChain = new ArrayList<>();
            List<String> names = new ArrayList<>();
            if (chain != null)
            {
                // extract names from first cert
                Set<String> nameSet = extractCertificateNames(chain[0]);
                nameSet.add(alias);
                names = new ArrayList<>(nameSet);
                for (Certificate c : chain)
                    certChain.add(new CertificateData(c));
            }

            KeyStoreEntry kse = new KeyStoreEntry(alias, creationDate, key, kp, certChain, names);
            kse.setLockedKeyProtection(kp.getLockedKeyProtection(publicKey));

            KeyStoreEntry kseOld = keystoreDAO.getEntry(alias);
            if (kseOld != null)
                keystoreDAO.deleteEntry(kseOld);
            keystoreDAO.setEntry(kse);
        }
        catch (KeyStoreDAOException | IOException | CertificateEncodingException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | CertificateParsingException | InvalidNameException e)
        {
            LOG.error(e, e);
            throw new KeyStoreException(e);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            Date creationDate = Date.from(Instant.now());
            KeyStoreEntry kse = new KeyStoreEntry(alias, creationDate, cert);
            KeyStoreEntry kseOld = keystoreDAO.getEntry(alias);
            if (kseOld != null)
            {
                if (kseOld.getEntryType() != KeyStoreEntryType.TRUSTED_CERTIFICATE)
                    throw new KeyStoreException("the given alias already exists and does not identify an entry containing a trusted certificate");

                keystoreDAO.deleteEntry(kseOld);
            }

            keystoreDAO.setEntry(kse);
        }
        catch (KeyStoreDAOException | IOException | CertificateEncodingException e)
        {
            LOG.error(e, e);
            throw new KeyStoreException(e);
        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            if (kse != null)
                keystoreDAO.deleteEntry(kse);
        }
        catch (KeyStoreDAOException | IOException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
            throw new KeyStoreException(e);
        }
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            List<String> aliases = keystoreDAO.getAliases();
            return Collections.enumeration(aliases);
        }
        catch (KeyStoreDAOException | IOException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
        }

        return Collections.emptyEnumeration();
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();
            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            return kse != null;
        }
        catch (KeyStoreDAOException | IOException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
        }

        return false;
    }

    @Override
    public int engineSize()
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            return keystoreDAO.countEntries();
        }
        catch (KeyStoreDAOException | IOException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
        }

        return 0;
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            if (kse == null)
                return false;

            return kse.getEntryType() != KeyStoreEntryType.TRUSTED_CERTIFICATE;
        }
        catch (KeyStoreDAOException | IOException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
        }

        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            KeyStoreEntry kse = keystoreDAO.getEntry(alias);
            if (kse == null)
                return false;

            return kse.getEntryType() == KeyStoreEntryType.TRUSTED_CERTIFICATE;
        }
        catch (KeyStoreDAOException | IOException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
        }

        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        try
        {
            checkKeyStoreDAOIsLoaded();

            List<String> aliases = keystoreDAO.getAliases();
            for (String alias : aliases)
            {
                KeyStoreEntry kse = keystoreDAO.getEntry(alias);
                Certificate c = null;
                try
                {
                    switch (kse.getEntryType())
                    {
                    case PRIVATE_KEY:
                        List<CertificateData> ce = kse.getCertificateChain();
                        if (!ce.isEmpty())
                            c = ce.get(0).getCertificate();
                        break;
                    case TRUSTED_CERTIFICATE:
                        c = kse.getTrustedCertificate();
                        break;
                    default:
                        continue;
                    }

                    if ((c != null) && cert.equals(c))
                        return alias;

                }
                catch (CertificateException e)
                {
                    LOG.warn(e);
                    LOG.debug(e, e);
                }
            }
        }
        catch (KeyStoreDAOException | IOException e)
        {
            LOG.error(e);
            LOG.debug(e, e);
        }

        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        checkKeyStoreDAOIsLoaded();

        try
        {
            keystoreDAO.checkDAOStructure();
            IntegrityData id = keystoreDAO.getIntegrityData();
            id = new IntegrityData(id.getSalt(), password);
            keystoreDAO.setIntegrityData(id);
        }
        catch (NullPointerException | KeyStoreDAOException e)
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
        checkKeyStoreDAOIsLoaded();

        try
        {
            keystoreDAO.checkDAOStructure();
            IntegrityData id = keystoreDAO.getIntegrityData();
            if (id == null)
            {
                id = new IntegrityData(password);
                keystoreDAO.setIntegrityData(id);
            }

            if (publicKey == null)
                publicKey = loadKeyProtectionPublicKey();

            if (password != null)
                id.checkIntegrity(password);
        }
        catch (UnrecoverableKeyException | InvalidKeySpecException e)
        {
            LOG.debug(e, e);
            LOG.error(e);
            throw new IOException(e);
        }
        catch (GeneralSecurityException | KeyStoreDAOException e)
        {
            LOG.debug(e, e);
            LOG.fatal(e);
            throw new NoSuchAlgorithmException(e);
        }
    }

    private void checkKeyStoreDAOIsLoaded() throws IOException
    {
        if (keystoreDAO == null)
        {
            final String errorMsg = "keystore dao is not loaded";
            LOG.fatal(errorMsg);
            throw new IOException(errorMsg);
        }
    }

    private PublicKey loadKeyProtectionPublicKey()
    {
        URL url = Thread.currentThread().getContextClassLoader().getResource(VR_KEYSTORE_PUBLIC_KEY_FILE);
        if (url == null)
            return null;

        try
        {
            byte[] encKey = Files.readAllBytes(Paths.get(url.toURI()));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new X509EncodedKeySpec(encKey));
        }
        catch (IOException | URISyntaxException e)
        {
            LOG.debug(e, e);
            LOG.warn("public key not found: keystore will not be protected", e);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            LOG.debug(e, e);
            LOG.warn("bad public key format: keystore will not be protected", e);
        }

        return null;
    }

    private Set<String> extractCertificateNames(Certificate cert) throws InvalidNameException, CertificateParsingException
    {
        Set<String> hosts = new HashSet<>();

        if (!X509Certificate.class.isInstance(cert))
            return hosts;

        X509Certificate x509 = (X509Certificate) cert;
        String dn = x509.getSubjectX500Principal().getName();
        LdapName ldapDN = new LdapName(dn);
        for (Rdn rdn : ldapDN.getRdns())
            if ("CN".equalsIgnoreCase(rdn.getType()))
            {
                String host = (String) rdn.getValue();
                LOG.debug("CN: " + host);
                hosts.add(host);
            }

        Collection<List<?>> altList = x509.getSubjectAlternativeNames();
        if (altList != null)
            for (List<?> alt : altList)
                if (((Integer) alt.get(0)).intValue() == 2) // 2 is a SubjectALT
                                                            // DNS name
                {
                    String host = (String) alt.get(1);
                    LOG.debug("alt DNS: " + host);
                    hosts.add(host);
                }

        return hosts;
    }
}
