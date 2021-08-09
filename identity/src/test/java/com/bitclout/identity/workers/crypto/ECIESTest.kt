package com.bitclout.identity.workers.crypto

import com.bitclout.identity.workers.crypto.ECIES.randomBytes
import org.junit.Test
import org.junit.jupiter.api.Assertions.*
import java.math.BigInteger
import java.util.*

class ECIESTest {

    @Test
    fun `Can create random bytes of given length`() {
        val actualBytes = randomBytes(32)
        assertEquals(32, actualBytes.count())
    }

    @Test
    fun `Two created random bytes don't have the same average`() {
        val actualBytes1 = randomBytes(32)
        val actualBytes2 = randomBytes(32)
        assertNotEquals(actualBytes1.average(), actualBytes2.average())
    }

    @Test
    fun `Can get SECP256K1 public key from private key`() {
        val privateKeyNum =
            "13836236946330594351194505494576451025382119209617992394589229203957340004156"
        val hexPublicKeyExpected =
            "04540f1750869cc1eb0272597523a0397d8b57caee290aaf9020efcb00e651fd98df34e4e4702f9e62b9cfa7e994858f1ec22717e52183697841cf99af14243e5d"

        val privateKey = BigInteger(privateKeyNum).toByteArray()
        val publicKey = ECIES.getPublicKeyFromECPrivateKey(privateKey)
        val publicKeyString = Base64.getEncoder().encodeToString(publicKey)
        val expectedPublicKeyString =
            Base64.getEncoder().encodeToString(hexPublicKeyExpected.decodeHex())
        assertEquals(expectedPublicKeyString, publicKeyString)
    }

    @Test
    fun `Derived value from two key pairs is the same using private from one and public from other`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val derivedOne = ECIES.derive(keyPairOne.first, keyPairTwo.second)
        val derivedTwo = ECIES.derive(keyPairTwo.first, keyPairOne.second)
        assertTrue(derivedOne.contentEquals(derivedTwo))
    }

    @Test
    fun `Derived value is different when not using the same 2 key pairs`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val keyPairThree = getRandomKeypair()
        val derivedOne = ECIES.derive(keyPairOne.first, keyPairTwo.second)
        val derivedTwo = ECIES.derive(keyPairTwo.first, keyPairThree.second)
        assertFalse(derivedOne.contentEquals(derivedTwo))
    }

    @Test
    fun `Can encrypt and decrypt a message from a shared secret`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val messageText = "Hello, World!"
        val sharedSecret = ECIES.derive(keyPairOne.first, keyPairTwo.second)
        val encryptedMessage = ECIES.encryptShared(sharedSecret, messageText.toByteArray())
        val decrypted = ECIES.decryptShared(sharedSecret, encryptedMessage)
        val decryptedMessage = decrypted.toString(Charsets.UTF_8)
        assertEquals(messageText, decryptedMessage)
    }

    @Test
    fun `Can encrypt and decrypt a message from with known keys`() {
        val keyA = "2065197619278232207331850954398649548439536519029151570985531343098926197990"
        val keyB = "50230616282125094136534483507073591524680824893410640560691205122786740086622"
        val keyPairOne = getKeypairFromPrivateIntString(keyA)
        val keyPairTwo = getKeypairFromPrivateIntString(keyB)
        val messageText = "Hello, World!"
        val sharedSecret = ECIES.derive(keyPairOne.first, keyPairTwo.second)
        val encryptedMessage = ECIES.encryptShared(sharedSecret, messageText.toByteArray())
        val decrypted = ECIES.decryptShared(sharedSecret, encryptedMessage)
        val decryptedMessage = decrypted.toString(Charsets.UTF_8)
        assertEquals(messageText, decryptedMessage)
    }

    @Test
    fun `Can verify data that has been signed by a private key`() {
        val keyPair = getRandomKeypair()
        val data = randomBytes(32)
        val signedData = ECIES.sign(keyPair.first, data)
        val verified = ECIES.verify(keyPair.second, data, signedData)
        assertTrue(verified)
    }

    @Test
    fun `Verify data is false that has been signed by a different key`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val data = randomBytes(32)
        val signedData = ECIES.sign(keyPairOne.first, data)
        val verified = ECIES.verify(keyPairTwo.second, data, signedData)
        assertFalse(verified)
    }

    private fun getRandomKeypair(): Pair<ByteArray, ByteArray> {
        val privateKey = randomBytes(32)
        val publicK = ECIES.getPublicKeyFromECPrivateKey(privateKey)
        return Pair(privateKey, publicK)
    }

    private fun getKeypairFromPrivateIntString(private: String): Pair<ByteArray, ByteArray> {
        val privateKey = BigInteger(private).toByteArray()
        val publicK = ECIES.getPublicKeyFromECPrivateKey(privateKey)
        return Pair(privateKey, publicK)
    }

    private fun String.decodeHex(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}