package com.vaderetrosecure.keystore.dao.sql;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({
    EncodingToolsTest.class,
    SqlKeyStoreDAOTest.class,
    SqlKeyStoreDAOFactoryTest.class
})
public class AllTests
{
}
