# Vade Retro Provider

## Overview

The Vade Retro Provider library offers tools to manage keys and certificates dynamically over a DAO architecture. It provides the following services (names), pluggable into the Java Cryptography Architecture and the Java Secure Socket Extension:
* the Vade Retro keystore
* the Vade Retro X509 key manager factory
* the Vade Retro SSL context, managing SNI over default SSL protocols.

## Requirements

To work, the provider needs:
* to run on Java 8 JVMs or higher
* to use unlimited JCE (download at http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

## Project structure

This project is divided into 2 sub projects:
* [Provider Core](provider-core), the core library that gives all the services
* [Provider Keystore SQL](provider-keystore-sql), a SQL implementation of the DAO.
