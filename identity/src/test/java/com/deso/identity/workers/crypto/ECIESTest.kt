package com.deso.identity.workers.crypto

import com.deso.identity.workers.crypto.Base58
import com.deso.identity.decodeHex
import org.junit.Test
import org.junit.jupiter.api.Assertions.*
import java.math.BigInteger
import java.util.*

class ECIESTest {

    val testSeedHex = "db24537899d239c5dbdca9d6d04c1cf14495fcdc4ca10b59223436f2156353ea"

    @Test
    fun `Can create random bytes of given length`() {
        val ecies = ECIES()
        val actualBytes = ecies.randomBytes(32)
        assertEquals(32, actualBytes.count())
    }

    @Test
    fun `Two created random bytes don't have the same average`() {
        val ecies = ECIES()
        val actualBytes1 = ecies.randomBytes(32)
        val actualBytes2 = ecies.randomBytes(32)
        assertNotEquals(actualBytes1.average(), actualBytes2.average())
    }

    @Test
    fun `Can get SECP256K1 public key from private key`() {
        val privateKeyNum =
            "13836236946330594351194505494576451025382119209617992394589229203957340004156"
        val hexPublicKeyExpected =
            "04540f1750869cc1eb0272597523a0397d8b57caee290aaf9020efcb00e651fd98df34e4e4702f9e62b9cfa7e994858f1ec22717e52183697841cf99af14243e5d"
        val ecies = ECIES()
        val privateKey = BigInteger(privateKeyNum).toByteArray()
        val publicKey = ecies.getPublicKeyFromECPrivateKey(privateKey)
        val publicKeyString = Base64.getEncoder().encodeToString(publicKey)
        val expectedPublicKeyString =
            Base64.getEncoder().encodeToString(hexPublicKeyExpected.decodeHex())
        assertEquals(expectedPublicKeyString, publicKeyString)
    }

    @Test
    fun `Derived value from two key pairs is the same using private from one and public from other`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val ecies = ECIES()
        val derivedOne = ecies.derive(keyPairOne.first, keyPairTwo.second)
        val derivedTwo = ecies.derive(keyPairTwo.first, keyPairOne.second)
        assertTrue(derivedOne.contentEquals(derivedTwo))
    }

    @Test
    fun `Derived value is different when not using the same 2 key pairs`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val keyPairThree = getRandomKeypair()
        val ecies = ECIES()
        val derivedOne = ecies.derive(keyPairOne.first, keyPairTwo.second)
        val derivedTwo = ecies.derive(keyPairTwo.first, keyPairThree.second)
        assertFalse(derivedOne.contentEquals(derivedTwo))
    }

    @Test
    fun `Can encrypt and decrypt a message from a shared secret`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val messageText = "Hello, World!"
        val ecies = ECIES()
        val sharedSecret = ecies.derive(keyPairOne.first, keyPairTwo.second)
        val encryptedMessage = ecies.encryptShared(sharedSecret, messageText.toByteArray())
        val decrypted = ecies.decryptShared(sharedSecret, encryptedMessage)
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
        val ecies = ECIES()
        val sharedSecret = ecies.derive(keyPairOne.first, keyPairTwo.second)
        val encryptedMessage = ecies.encryptShared(sharedSecret, messageText.toByteArray())
        val decrypted = ecies.decryptShared(sharedSecret, encryptedMessage)
        val decryptedMessage = decrypted.toString(Charsets.UTF_8)
        assertEquals(messageText, decryptedMessage)
    }

    @Test
    fun `Can decrypt a message encrypted from web Identity`() {
        val encryptedMessage = "04112898103de7db57ca86be6c06afae6d942a91a9f46f318c939c0b8d0a08a78e62f6266ca1248272edfd462c9c97f257c1b7f8510581217ed641fba5e328f18f6e57acca63f4287d86887390eba3892215291951a30916010b1d6ef557e2af5c54f4e43a0011feda1bfd9212e9beeabae136c942ba"
        val encryptedMessageBytes = BigInteger(encryptedMessage, 16).toByteArray()
        val senderPublicKey = "BC1YLgwikV34hZ2qgvWjhvSrbu7Pfs1AbfFJL3dWNJrjn1h2cySXXYr"
        val receiverPrivateKeyBytes = BigInteger(testSeedHex, 16).toByteArray()
        val decodedPublicKey = Base58.decodeChecked(senderPublicKey)
        val senderPublicKeyBytes = decodedPublicKey.sliceArray(3 until decodedPublicKey.count())
        val expectedMessageText = "Holla"
        val ecies = ECIES()
        val decrypted = ecies.decryptShared(receiverPrivateKeyBytes, senderPublicKeyBytes, encryptedMessageBytes)
        val decryptedMessage = decrypted.toString(Charsets.UTF_8)
        assertEquals(expectedMessageText, decryptedMessage)
    }

    @Test
    fun `Can sign a transaction and get an expected signed transaction hex`() {
        val inputHex = "01a148417f141e8bb5c59199d7ce3c9cf45abc31e8b1e216155daf677ac2a5805e000102f7e21a74c969d75e708391427a19e627f44731a0a63d0cd114f63b96a12d3442dfe13c0a21e17f98384111c7aec62640e80e6918893269e91264e35c7a2db2d2afd351d64f002102f7e21a74c969d75e708391427a19e627f44731a0a63d0cd114f63b96a12d34420000"
        val expected = "01a148417f141e8bb5c59199d7ce3c9cf45abc31e8b1e216155daf677ac2a5805e000102f7e21a74c969d75e708391427a19e627f44731a0a63d0cd114f63b96a12d3442dfe13c0a21e17f98384111c7aec62640e80e6918893269e91264e35c7a2db2d2afd351d64f002102f7e21a74c969d75e708391427a19e627f44731a0a63d0cd114f63b96a12d344200483046022100f8008f90549a3a5bac59b10e1162665e4039877a107cceaa10f7c59f9b026b1c022100930b5b4e20af40414543afcec42f1966d92aac92eb310565c58de465329131a6"
        val ecies = ECIES()
        val actual = ecies.signTransaction(testSeedHex, inputHex)
        assertEquals(expected, actual)
    }

    @Test
    fun `Can verify data that has been signed by a private key`() {
        val keyPair = getRandomKeypair()
        val ecies = ECIES()
        val data = ecies.randomBytes(32)
        val signedData = ecies.sign(keyPair.first, data)
        val verified = ecies.verify(keyPair.second, data, signedData)
        assertTrue(verified)
    }

    @Test
    fun `Verify data is false that has been signed by a different key`() {
        val keyPairOne = getRandomKeypair()
        val keyPairTwo = getRandomKeypair()
        val ecies = ECIES()
        val data = ecies.randomBytes(32)
        val signedData = ecies.sign(keyPairOne.first, data)
        val verified = ecies.verify(keyPairTwo.second, data, signedData)
        assertFalse(verified)
    }

    private fun getRandomKeypair(): Pair<ByteArray, ByteArray> {
        val ecies = ECIES()
        val privateKey = ecies.randomBytes(32)
        val publicK = ecies.getPublicKeyFromECPrivateKey(privateKey)
        return Pair(privateKey, publicK)
    }

    private fun getKeypairFromPrivateIntString(private: String): Pair<ByteArray, ByteArray> {
        val ecies = ECIES()
        val privateKey = BigInteger(private).toByteArray()
        val publicK = ecies.getPublicKeyFromECPrivateKey(privateKey)
        return Pair(privateKey, publicK)
    }
}
