package com.deso.identity.workers

import com.deso.identity.models.EncryptedMessagesThread
import com.deso.identity.models.SharedSecret
import com.deso.identity.workers.crypto.ECIES
import com.deso.identity.models.SharedSecretRequest

class MessageEncryptionWorker(private val keyStore: KeyInfoStorageWorker, private val ecies: ECIES) {

    fun encrypt(message: String, sharedSecret: String): String {
        val encryptedByteArray =
            ecies.encryptShared(sharedSecret.toByteArray(), message.encodeToByteArray())
        return encryptedByteArray.decodeToString()
    }

    fun decryptThreads(
        threads: List<EncryptedMessagesThread>,
        currentUserPublicKey: String,
        errorOnFailure: Boolean
    ): Map<String, List<String>> {
        val savedSecrets = keyStore.getSharedSecrets()
        val sharedSecretRequests = threads.filter { thread ->
            getSecretForThread(savedSecrets, currentUserPublicKey, thread) != null
        }.map { SharedSecretRequest(currentUserPublicKey, it.publicKey) }
        //TODO for any shared secrets not in storage request from web app
        val sharedSecrets = savedSecrets
        val results = mutableMapOf<String, List<String>>()
        return threads.fold(results, { output, thread ->
            runCatching {
                getSecretForThread(sharedSecrets, currentUserPublicKey, thread)?.let {
                    output[thread.publicKey] = decrypt(thread.encryptedMessages, it)
                }
            }.onFailure { if (errorOnFailure) throw it }
            output
        })
    }

    private fun getSecretForThread(
        savedSecrets: List<SharedSecret>,
        currentUserPublicKey: String,
        thread: EncryptedMessagesThread
    ) =
        savedSecrets.firstOrNull { it.ownPublicKey == currentUserPublicKey && it.otherPublicKey == thread.publicKey }

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
            ecies.decryptShared(secret.secret.toByteArray(), it.toByteArray()).decodeToString()
        }

    companion object {
        const val TEST_SECRET = "BBm0vS4e6E4FhrZa10PP4D8rqTq1wse7"
        const val TEST_PRIVATE_KEY = "NeNQQ6BSBLrpDPam3Eo7QlL6yC4wUO1m"
        const val TEST_PUBLIC_KEY = "KXklXfDc9gCjIRzyS6R4RtMkIhP8oqS4"
        val testSharedSecret =
            SharedSecret(TEST_SECRET, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY)
    }
}
