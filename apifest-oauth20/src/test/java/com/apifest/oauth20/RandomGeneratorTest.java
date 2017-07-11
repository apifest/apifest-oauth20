package com.apifest.oauth20;

import java.util.HashSet;

import org.testng.Assert;
import org.testng.annotations.Test;

public class RandomGeneratorTest {

    /**
     * Demonstrates approximate collision rate. It is disabled, because it is slow and unreliable - although collisions 
     * can be reduced, they can't be avoided
     */
    @Test(enabled = false)
    public void when_generate_random_string_then_inspect_collisions() {
        // GIVEN
        int invocationCount = 10 * 1000 * 1000;
        HashSet<String> uniqueStrings = new HashSet<String>();

        // WHEN
        for (int i = 0; i < invocationCount; ++i) {
            uniqueStrings.add(RandomGenerator.generateRandomString());
        }

        // THEN
        Assert.assertEquals(uniqueStrings.size(), invocationCount);
    }
}