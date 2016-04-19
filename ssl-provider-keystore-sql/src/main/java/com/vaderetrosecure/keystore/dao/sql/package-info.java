/**
 * This package contains an SQL implementation of the DAO.
 * <p>
 * <b>Database Architecture</b>
 * <p>
 * It uses the following database architecture:
 * <p>
 * <img src="doc-files/keystore-dao-sql.png" alt="SQL database implementation">
 * <p>
 * The implementation is responsible of creating, managing and eventually updating tables. So, only the database needs 
 * to be created. For example, in MySQL, the database {@code KeyStore} will be created like this:
 * <pre>
 * {@code create database KeyStore;}</pre>
 * When manipulation the architecture, the user can drop, delete, select, insert and alter all tables 
 * from the database. In MySQL, it can be done with the command:
 * <pre>
 * {@code grant all privileges on KEYSTORE.* to 'keystore'@'%' identified by 'keystore';}</pre>
 * <p>
 * <b>Improving Database Security</b>
 * <p>
 * The goal is to separate key store manipulation and SSL context use. In the app using the key store, a database user 
 * will have high access rights to modify the key store. In the app using SSL context, a user only needs to read the 
 * key store. So the associated database user will only have read access rights to tables. 
 * 
 * @author ahonore
 */
package com.vaderetrosecure.keystore.dao.sql;