/**
 * 
 */
package com.vaderetrosecure;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.sql.DataSource;

import org.apache.commons.dbcp2.ConnectionFactory;
import org.apache.commons.dbcp2.DriverManagerConnectionFactory;
import org.apache.commons.dbcp2.PoolableConnection;
import org.apache.commons.dbcp2.PoolableConnectionFactory;
import org.apache.commons.dbcp2.PoolingDataSource;
import org.apache.commons.pool2.ObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.eclipse.jetty.util.ssl.SniX509ExtendedKeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.vaderetrosecure.ssl.VRX509KeyManager;

/**
 * @author ahonore
 *
 */
public class SqlCertificatesLoader
{
    private final static Logger LOGGER = LoggerFactory.getLogger(SqlCertificatesLoader.class);

    private String databasePath;
    private String keystorePath;
    private String keyManagerPassword;
    private String keystorePassword;
    private KeyManager[] keyManagers;
    
    public SqlCertificatesLoader(String databasePath, String keystorePath, String keyManagerPassword, String keystorePassword)
    {
        this.databasePath = databasePath;
        this.keystorePath = keystorePath;
        this.keyManagerPassword = keyManagerPassword;
        this.keystorePassword = keystorePassword;
        keyManagers = new KeyManager[]{};
    }

    /**
     * read from db and store into the keystore
     */
    public void load() throws Exception
    {
        List<AccountCertificateInfo> accountCerts = Collections.emptyList();
        try (PoolingDataSource<PoolableConnection> dataSource = getDataSource())
        {
            accountCerts = getAccountCertificateEntries(dataSource);
        }

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
//        keystore.load(null);
        try (InputStream is = new FileInputStream(keystorePath))
        {
            keystore.load(is, keyManagerPassword.toCharArray());
        }
        
        for (AccountCertificateInfo aci : accountCerts)
        {
            keystore.setKeyEntry(aci.getHostname(), aci.getPrivateKey(), keystorePassword.toCharArray(), aci.getCertificateChain().toArray(new Certificate[]{}));
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keystore, keystorePassword.toCharArray());
        keyManagers = kmf.getKeyManagers();
        for (int i = 0 ; i < keyManagers.length ; i++)
        {
            keyManagers[i] = new VRX509KeyManager((X509ExtendedKeyManager) keyManagers[i]);
//            keyManagers[i] = new SniX509ExtendedKeyManager((X509ExtendedKeyManager) keyManagers[i]);
        }

        try (OutputStream os = new FileOutputStream(keystorePath))
        {
            keystore.store(os, keyManagerPassword.toCharArray());
        }
    }
    
    public KeyManager[] getKeyManagers()
    {
        return keyManagers;
    }
    
    private PoolingDataSource<PoolableConnection> getDataSource() throws Exception
    {
        Properties p = new Properties();
        try (FileInputStream is = new FileInputStream(new File(databasePath)))
        {
            p.load(is);
        }
        catch (IOException e)
        {
            LOGGER.error(e.getMessage(), e);
            throw e;
        }
        
        try {
            String driver = p.getProperty("driverClassName", "com.mysql.jdbc.Driver");
            if ((driver == null) || driver.isEmpty()) {
                throw new Exception("invalid driver classname");
            }
            String url = p.getProperty("url");
            if ((url == null) || url.isEmpty()) {
                throw new Exception("connection url not found");
            }
//            String user = p.getProperty("user");
//            if ((user == null) || user.isEmpty()) {
//                throw new Exception("user is missing");
//            }
//            String password = p.getProperty("password");
//            if ((user == null) || user.isEmpty()) {
//                throw new Exception("password is missing");
//            }

            Class.forName(driver);
            ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(url, p);
            PoolableConnectionFactory poolableConnectionFactory = new PoolableConnectionFactory(connectionFactory, null);
            ObjectPool<PoolableConnection> connectionPool = new GenericObjectPool<>(poolableConnectionFactory);
            poolableConnectionFactory.setPool(connectionPool);
            return new PoolingDataSource<>(connectionPool);
        } catch (ClassNotFoundException e) {
            LOGGER.equals(e.toString());
            throw e;
        }
    }
    
    private List<AccountCertificateInfo> getAccountCertificateEntries(DataSource dataSource) throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException
    {
        List<AccountCertificateInfo> certifList = new ArrayList<>();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        try (Connection conn = dataSource.getConnection())
        {
            try (PreparedStatement ps = conn.prepareStatement("select * from ACCOUNT_CERTIFICATE_INFO");PreparedStatement psCert = conn.prepareStatement("select * from CERTIFICATE_CHAINS where ACCOUNT_CERTIFICATE_INFO_ID=? order by SORTING_ID"))
            {
                ResultSet rs = ps.executeQuery();
                while (rs.next())
                {
                    AccountCertificateInfo aci = new AccountCertificateInfo();
                    aci.setHostname(rs.getString("HOSTNAME"));
                    Blob b = rs.getBlob("PRIVATE_KEY");
                    PrivateKey pk = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(b.getBytes(1, (int) b.length())));
                    aci.setPrivateKey(pk);
                    aci.setHostname(rs.getString("HOSTNAME"));
                    
                    psCert.setLong(1, rs.getLong("ACCOUNT_ID"));
                    try (ResultSet rsCert = psCert.executeQuery())
                    {
                        while (rsCert.next())
                        {
                            Blob bCert = rsCert.getBlob("CERTIFICATE");
                            Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(bCert.getBytes(1, (int) bCert.length())));
                            aci.getCertificateChain().add(cert);
                        }
                    }
                    certifList.add(aci);
                }   
            }
        }
        
        return certifList;
    }
}
