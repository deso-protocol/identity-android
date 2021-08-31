package com.deso.identity.workers

import com.deso.identity.models.EncryptedMessagesThread
import com.deso.identity.models.SharedSecret
import com.deso.identity.workers.crypto.ECIES
import io.mockk.MockKAnnotations
import io.mockk.every
import io.mockk.impl.annotations.MockK
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions
import java.util.*

class MessageEncryptionWorkerTest {

    @MockK
    lateinit var keystore: KeyInfoStorageWorker
    @MockK
    lateinit var ecies: ECIES

    @Before
    fun setUp() = MockKAnnotations.init(this)

    @Test
    fun `Can decrypt threads for shared secrets in storage`() {
        val ownKey = "OWN KEY"
        val otherKeyOne = "OTHER KEY ONE"
        val encryptedMessageOne = "whuuhvwuvhoiwviwn"
        val decryptedMessageOne = "This is the message"
        val secret = "SECRET"
        val sharedSecretOne = SharedSecret(secret, ownKey, otherKeyOne)
        val worker = MessageEncryptionWorker(keystore, ecies)
        every { keystore.getSharedSecrets() } returns listOf(sharedSecretOne)
        every { ecies.decryptShared(secret.toByteArray(), encryptedMessageOne.toByteArray()) } returns decryptedMessageOne.toByteArray()
        val threads = listOf(EncryptedMessagesThread(otherKeyOne, listOf(encryptedMessageOne)))
        val results = worker.decryptThreads(threads, ownKey, true)
        val decryptedThread = results[otherKeyOne]
        assertNotNull(decryptedThread)
        assertEquals(1, decryptedThread?.size)
        assertEquals(decryptedMessageOne, decryptedThread?.get(0))
    }

    @Test
    fun `If shared secret isn't in storage, get from web app`() {
        val ownKey = "OWN KEY"
        val otherKeyOne = "OTHER KEY ONE"
        val otherKeyTwo = "OTHER KEY TWO"
        val encryptedMessageOne = "whuuhvwuvhoiwviwn"
        val decryptedMessageOne = "This is the message"
        val secretOne = "SECRET_ONE"
        val secretTwo = "SECRET_TWO"
        val sharedSecretTwo = SharedSecret(secretTwo, ownKey, otherKeyTwo)
        val worker = MessageEncryptionWorker(keystore, ecies)
        every { keystore.getSharedSecrets() } returns listOf(sharedSecretTwo)
        every { ecies.decryptShared(secretOne.toByteArray(), encryptedMessageOne.toByteArray()) } returns decryptedMessageOne.toByteArray()
        val threads = listOf(EncryptedMessagesThread(otherKeyOne, listOf(encryptedMessageOne)))
        val results = worker.decryptThreads(threads, ownKey, true)
        val decryptedThread = results[otherKeyOne]
        assertNotNull(decryptedThread)
        assertEquals(1, decryptedThread?.size)
        assertEquals(decryptedMessageOne, decryptedThread?.get(0))
    }
}