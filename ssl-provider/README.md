# Vade Retro SSL Provider

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
```bash
java -Dcom.vaderetrosecure.keystore.dao.factory=com.mycompany.MyDAOFactoryImpl my-project.jar
```

## Implementing a DAO

To implement a DAO, make an implementation of the `com.vaderetrosecure.keystore.dao.KeyStoreDAO` interface. Then you must implement a DAO factory by extending the `com.vaderetrosecure.keystore.dao.KeyStoreDAOFactory` class. This class will be the entry point of the provider, using the parameter given in the previous section.
