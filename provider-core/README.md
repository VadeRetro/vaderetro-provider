# Vade Retro Provider: Provider Core

## Overview

This library provides the core of the services. It includes the following engine implementations:

| Engine | Name | Description |
|--------|--------|--------|
| KeyStore | KS | a keystore that dynamically manages certificates and keys over a DAO |
| KeyManagerFactory | X509 | a factory to provide X509 key managers over a DAO |
| SSLContext | TLS | a SSL context, backed by the default TLS SSL context of Java, that manages the SNI extension and can use the VR X509 key managers |


## Adding the Provider to your project

You can add it dynamically to your code or statically for all the JVM instances.

### Dynamic Registration

To register dynamically the provider, just put one line of code into a static block somewhere in a class:

```java
static
{
	Security.addProvider(new VadeRetroProvider());
}
```

Now, you're ready to play with it.

### Static Registration

To register statically the provider, please follow the explanations from the [Java Cryptography Architecture (JCA) Reference Guide](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#ProviderInstalling).

## Setting the DAO factory

To use a DAO implementation, you must inform the provider which DAO factory to instantiate. The provider will try to get the `com.vaderetrosecure.keystore.dao.factory` system variable. To set it, just put an argument in the command line, like this:

	java -Dcom.vaderetrosecure.keystore.dao.factory=com.mycompany.MyDAOFactoryImpl my-project.jar

## Using the keystore

To use the keystore from the Vade Retro Provider, just follow the usual access process:

```java
char[] password = getPassword(...);
KeyStore ks = KeyStore.getInstance("KS", "VR");
ks.load(null, password);
...
```

Then follow the methods of the KeyStore engine, defined in Java.


## Using the SSL context

### Creating the context

To use the SSL context from the Vade Retro Provider, just follow the usual access process:

```java
// get a keystore instance
char[] password = getPassword(...);
KeyStore ks = KeyStore.getInstance("KS", "VR");

// get an instance of the Vade Retro X509  key manager factory
KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509", "VR");
kmf.init(KeyStore.getInstance("KS", "VR"), null);

// create a TLS context with dynamic keys management
SSLContext sslCtx = SSLContext.getInstance("TLS", "VR");
sslCtx.init(kmf.getKeyManagers(), null, null);
...
```

### Using it with Jetty

Now, let's see you how to use it in web applications with Jetty. Just keep in mind that it must run with Jetty 9.3.4.v20151007 or higher.

The main goal is to replace the default Jetty class `SslContextFactory` behavior with ours. In general, the context is set by defining an usual key store, like this:

```java
SslContextFactory sslContextFactory = new SslContextFactory();
sslContextFactory.setKeyStorePath("path/to/keystore.jks");
sslContextFactory.setKeyStorePassword("a password");
sslContextFactory.setKeyManagerPassword("an other password");
```

which creates a default SSLContext Java object internally. Then, we use our code to create our own SSLContext object and override the Jetty one:

```java
// get a keystore instance
char[] password = getPassword(...);
KeyStore ks = KeyStore.getInstance("KS", "VR");

// get an instance of the Vade Retro X509  key manager factory
KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509", "VR");
kmf.init(KeyStore.getInstance("KS", "VR"), null);

// create a TLS context with dynamic keys management
SSLContext sslCtx = SSLContext.getInstance("TLS", "VR");
sslCtx.init(kmf.getKeyManagers(), null, null);

// now, set it in the Jetty SslContextFactory
SslContextFactory sslContextFactory = new SslContextFactory();
sslContextFactory.setSslContext(sslCtx);
``` 

Then, we can end the HTTPS connector declaration as usual:

```java
// a server and an HTTP configuration must be defined first
Server server = new Server(...);
HttpConfiguration httpConfiguration = new HttpConfiguration();
...

// an HTTP connector can be used
ServerConnector httpConnector = new ServerConnector(server, new HttpConnectionFactory(httpConfiguration));
...
server.addConnector(httpConnector);

// now, the HTTPS configuration object can be created
HttpConfiguration httpsConfiguration = new HttpConfiguration(httpConfiguration);
httpsConfiguration.addCustomizer(new SecureRequestCustomizer(true));

// HTTPS connector
ServerConnector httpsConnector = new ServerConnector(server, 
	new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
	new HttpConnectionFactory(httpsConfiguration));

// add the connector to the server
server.addConnector(httpsConnector);

```

Now, your code is ready to use our SSLContext with SNI and an implementation of a DAO. 

## Improving security (since version 0.4.0)

Contrary to usual implementations of a key store, KeyStore and KeyManager objects just have a reference of the DAO. This means that the KeyManager object resolves all password protections dynamically to access keys at any time. But it can't because only the KeyStore object works with passwords.

So, to be able to access keys, each password protection is stored with the key and ciphered using a public key from the KeyStore object. Then, each KeyManager object loads a private key to decipher the password protection and decipher the key with it.

Consistency of KeyStore and KeyManager contracts are preserved because:
* the KeyStore object must use password, because it can't decipher with its public key
* the KeyManager object can __only__ decipher with its private key and never modify the referenced DAO.

The KeyStore object will try to load the file `com.vaderetrosecure.key.public` as the public key from the classpath. The KeyManager will try to load the file `com.vaderetrosecure.key.private` as the private key from the classpath.

To use this security improvement, please, follow these steps:

* generate a key pair (at least 2048-bit long):

```
openssl genrsa -out private.key.pem 2048
openssl rsa -in private.key.pem -pubout -out public.key.pem
```

* convert the private key in __PKCS8 DER__ format:

```
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.key.pem  -nocrypt > com.vaderetrosecure.key.private
```

* convert the public key in __X509 DER__ format:

```
openssl rsa -pubin -in public.key.pem -outform der -pubout -out com.vaderetrosecure.key.public
```

* put the file `com.vaderetrosecure.key.public` in the classpath of your app managing the key store (KeyStore object).

* put the file `com.vaderetrosecure.key.private` in the classpath of your app reading the key store (KeyManager object).

Remember that you can not to use this security improvement, but any entity that access to the DAO can decipher and modify stored keys. __It's strongly discouraged__. 

## Implementing a DAO

To implement a DAO, make an implementation of the `com.vaderetrosecure.keystore.dao.KeyStoreDAO` interface. Then you must implement a DAO factory by extending the `com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory` class. This class will be the entry point of the provider, using the parameter given in the previous section.
