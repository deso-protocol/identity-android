package com.bitclout.identity.workers.crypto

import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import java.math.BigInteger

class ECIESTest {

    @Test
    fun `Can create random bytes of given length`() {
        val actualBytes = ECIES.randomBytes(32)
        assertEquals(32, actualBytes.count())
    }

    @Test
    fun `Two created random bytes don't have the same average`() {
        val actualBytes1 = ECIES.randomBytes(32)
        val actualBytes2 = ECIES.randomBytes(32)
        assertNotEquals(actualBytes1.average(), actualBytes2.average())
    }

    @Test
    fun `Can create a private key`() {
        val expectedPrivateNumber = BigInteger(SAMPLE_PRIVATE_KEY, 16)
        val ecPrivateKey = ECIES.getECPrivateKeyFromByteArray(expectedPrivateNumber.toByteArray())
        assertEquals(expectedPrivateNumber, ecPrivateKey.d)
    }

    @Test
    fun `Can create a key pair`() {
        val keys = ECIES.getECKeyPair()
        assertEquals("EC", keys.first.algorithm)
        assertEquals("PKCS#8", keys.first.format)
        assertEquals(32, keys.first.s.toByteArray().count())
    }

    companion object {
        private const val SAMPLE_PRIVATE_KEY = "1b9cdf53588f99cea61c6482c4549b0316bafde19f76851940d71babaec5e569"
    }
}