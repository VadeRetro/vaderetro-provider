package com.vaderetrosecure;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.vaderetrosecure.keystore.VRKeystoreSpiTest;
import com.vaderetrosecure.keystore.dao.KeyStoreMetaDataTest;

@RunWith(Suite.class)
@SuiteClasses({
    VadeRetroProviderTest.class,
    KeyStoreMetaDataTest.class,
    VRKeystoreSpiTest.class
})
public class AllTests
{
}
