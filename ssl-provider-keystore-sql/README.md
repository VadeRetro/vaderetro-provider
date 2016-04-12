# Vade Retro SSL Provider: SQL keystore implementation

## Overview

This library implements a SQL keystore DAO from the SSL provider.

## Setting the DAO factory

This factory will be loaded by the provider by settings the system variable at the command line like this:

```bash
java -Dcom.vaderetrosecure.keystore.dao.factory=com.vaderetrosecure.keystore.dao.sql.SqlKeyStoreDAOFactory my-project.jar
```

## Defining the DAO property file

This DAO uses a property file to declare connection pool and driver values. This file must be located in the classpath and have the name `com.vaderetrosecure.keystore.dao.properties`. Here is an example of such a file:

```
driverClassName = com.mysql.jdbc.Driver
url = jdbc:mysql://192.168.15.68/KEYSTORE
user = keystore
password = keystore
maxActive = 100
maxIdle = 30
maxWait = 10000
removeAbandoned = true
removeAbandonedTimeout = 60
logAbandoned = true
```

## Setting the database

Before launching the application, be sure your database server is configured correctly: 
* a database must exist, with the name defined in the url of the property file. In our MySQL example, it can be done with the command:

```
create database KEYSTORE;
```

* the created user must have all privileges in the database. In our MySQL example, it can be done with the command:

```
grant all privileges on KEYSTORE.* to 'keystore'@'%' identified by 'keystore';
```
