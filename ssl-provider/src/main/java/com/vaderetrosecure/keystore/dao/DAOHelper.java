/**
 * 
 */
package com.vaderetrosecure.keystore.dao;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;

/**
 * @author ahonore
 *
 */
public final class DAOHelper
{
    private final static Logger LOG = Logger.getLogger(DAOHelper.class);

	private DAOHelper()
	{
	}
	
	public static PrivateKey getPrivateKey(KeyStoreDAO keyStoreDAO, KeyStoreMetaData keyStoreMetaData, String alias) throws KeyStoreDAOException, NoSuchAlgorithmException
	{
		List<KeyStoreEntry> entries = keyStoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.PRIVATE_KEY);
		if (entries.isEmpty())
			return null;

		KeyStoreEntry kse = entries.get(0);
		KeyFactory kf = KeyFactory.getInstance(kse.getAlgorithm());
		try
		{
			return kf.generatePrivate(new PKCS8EncodedKeySpec(keyStoreMetaData.decipherKeyEntry(null, kse.getData())));
		}
        catch (InvalidAlgorithmParameterException e)
        {
            LOG.error(e, e);
            throw new NoSuchAlgorithmException(e);
        }
		catch (InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e)
		{
			LOG.error(e, e);
			throw new KeyStoreDAOException(e);
		}
	}

	public static List<Certificate> getListOfCertificates(KeyStoreDAO keyStoreDAO, String alias) throws KeyStoreDAOException, CertificateException
    {
		List<KeyStoreEntry> entries = keyStoreDAO.getKeyStoreEntry(alias, KeyStoreEntryType.CERTIFICATE);
		if (entries.isEmpty())
			return Collections.emptyList();
            	
		List<Certificate> certChain = new ArrayList<>();
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
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
}
