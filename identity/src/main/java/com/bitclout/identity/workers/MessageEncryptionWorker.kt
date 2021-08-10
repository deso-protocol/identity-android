package com.bitclout.identity.workers

import com.bitclout.identity.models.EncryptedMessagesThread
import com.bitclout.identity.models.SharedSecret
import com.bitclout.identity.workers.crypto.ECIES
import com.bitclout.identity.workers.crypto.ECIES.decryptShared
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class MessageEncryptionWorker {

    fun encrypt(message: String, sharedSecret: String): String {
        val encryptedByteArray = ECIES.encryptShared(sharedSecret.toByteArray(), message.encodeToByteArray())
        return encryptedByteArray.decodeToString()
    }

    fun decryptThreads(
        encryptedMessageThreads: List<EncryptedMessagesThread>,
        publicKey: String,
        errorOnFailure: Boolean
    ): Map<String, List<String>> {
        val results = mutableMapOf<String, List<String>>()
        return encryptedMessageThreads.fold(results, { output, thread ->
            runCatching {
                output[thread.publicKey] = decryptThread(thread, publicKey, errorOnFailure)
            }.onFailure { if (errorOnFailure) throw it }
            output
        })
    }

    fun decryptThread(
        thread: EncryptedMessagesThread,
        publicKey: String,
        errorOnFailure: Boolean
    ): List<String> {
        //TODO: get actual SharedSecret from KeyInfoStorageWorker
        val sharedSecret = testSharedSecret
        var result = emptyList<String>()
        runCatching { result = decrypt(thread.encryptedMessages, sharedSecret) }
            .onFailure { if (errorOnFailure) throw it }
        return result
    }

    private fun decrypt(messages: List<String>, secret: SharedSecret): List<String> =
        messages.map {
            decryptShared(secret.secret.toByteArray(), it.toByteArray()).decodeToString()
        }

    companion object {
        const val TEST_SECRET = "BBm0vS4e6E4FhrZa10PP4D8rqTq1wse7"
        const val TEST_PRIVATE_KEY = "NeNQQ6BSBLrpDPam3Eo7QlL6yC4wUO1m"
        const val TEST_PUBLIC_KEY = "KXklXfDc9gCjIRzyS6R4RtMkIhP8oqS4"
        const val TEST_TRUE_PUBLIC_KEY = "UJ1JwCkYJz3FHrb48sS6DjQFA3NNmRAG"
        val testSharedSecret =
            SharedSecret(TEST_SECRET, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, TEST_TRUE_PUBLIC_KEY)
    }
}
