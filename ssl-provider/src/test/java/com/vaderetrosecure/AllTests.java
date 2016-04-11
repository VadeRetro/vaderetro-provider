package com.vaderetrosecure;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.vaderetrosecure.keystore.VRKeyStoreSpiTest;
import com.vaderetrosecure.keystore.dao.IntegrityDataTest;
import com.vaderetrosecure.ssl.SNIX509ExtendedKeyManagerTest;

@RunWith(Suite.class)
@SuiteClasses({
    VadeRetroProviderTest.class,
    IntegrityDataTest.class,
    VRKeyStoreSpiTest.class,
    SNIX509ExtendedKeyManagerTest.class
})
public class AllTests
{
}
