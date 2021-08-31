package com.deso.identity

import android.content.Context
import com.deso.identity.models.EncryptedMessagesThread
import com.deso.identity.workers.AuthWorker
import com.deso.identity.workers.KeyInfoStorageWorker
import com.deso.identity.workers.MessageEncryptionWorker
import com.deso.identity.workers.TransactionSigner
import com.deso.identity.workers.crypto.ECIES

object Identity {

    private var applicationContext: Context? = null
    private val authWorker = AuthWorker()
    private val ecies = ECIES()
    lateinit var keyStore: KeyInfoStorageWorker
    lateinit var messageEncryptionWorker: MessageEncryptionWorker
    private lateinit var transactionSigner: TransactionSigner

    fun initialize(context: Context) {
        applicationContext = context
        keyStore = KeyInfoStorageWorker(context)
        messageEncryptionWorker = MessageEncryptionWorker(keyStore, ecies)
        transactionSigner = TransactionSigner(keyStore, ecies)
    }

    fun login(context: Context) {
        authWorker.navigateToLogin(context)
    }

    /**
    Call this to log an account out
    - Parameter publicKey: The true public key of the account to be logged out
    - Returns: An array of the remaining logged in true public keys
     */
    fun logout(publicKey: String): List<String> {
        keyStore.removeDerivedKeyInfo(publicKey)
        keyStore.setStoredKeys(getLoggedInKeys().filterNot { it == publicKey })
        //TODO: when an account is logged out, presumably we also need to delete any shared secrets relating to its private key?
        return keyStore.getAllStoredKeys()
    }

    /**
    Get a list of the true public keys currently logged in
    - Returns: An array of all the currently logged in true public keys
     */
    fun getLoggedInKeys(): List<String> = keyStore.getAllStoredKeys()

    /**
    Remove all the info currently stored
     */
    fun removeAllKeys() = keyStore.clearAllStoredInfo()

    /**
    Sign a transaction to be committed to the blockchain. Note, this does not write the transaction, it just signs it.
    - Parameter transaction: and `UnsignedTransaction` object to be signed
    - Returns: A signed hash of the transaction
     */
    fun sign(currentUserPublicKey: String, transactionHex: String): String =
        transactionSigner.signTransaction(currentUserPublicKey, transactionHex)

    /**
    Decrypt private messages from a collection of threads
    - Parameters:
    - threads: An array of `EncryptedMessagesThread` objects to be decrypted
    - myPublicKey: The public key of the calling user's account
    - errorOnFailure: true if failure to decrypt messages should return an error, false if messages which cannot be decrypted should just be ommitted from the results
    - Returns: A dictionary with keys of the publicKeys of the threads and values of the messages contained in the thread, in the order they were sent
     */
    fun decrypt(
        threads: List<EncryptedMessagesThread>,
        currentUserPublicKey: String,
        errorOnFailure: Boolean = false
    ): Map<String, List<String>> = messageEncryptionWorker.decryptThreads(threads, currentUserPublicKey, errorOnFailure)


    /**
    Decrypt private messages from a single thread
    - Parameters:
    - thread: An `EncryptedMessagesThread` object to be decrypted
    - myPublicKey: The public key of the calling user's account
    - errorOnFailure: true if failure to decrypt messages should return an error, false if messages which cannot be decrypted should just be ommitted from the results
    - Returns: An array of decrypted message strings in the order they were sent
     */
    fun decrypt(
        thread: EncryptedMessagesThread,
        myPublicKey: String,
        errorOnFailure: Boolean = false
    ): List<String> = messageEncryptionWorker.decryptThread(thread, myPublicKey, errorOnFailure)

    /**
    Encrypt private message
    - Parameters:
    - message: A message string to be encrypted
    - myPublicKey: The public key of the calling user's account
    - Returns: Encrypted message string
     */
    fun encrypt(message: String, currentUserPublicKey: String, recipientPublicKey: String): String {
        //TODO: get shared secret for conversation from storage
        // if null, make call to web identity for shared secret and store
        val sharedSecret = "placeholdersharedsecret"
        return messageEncryptionWorker.encrypt(message, sharedSecret)
    }

    /**
    Retrieve a JWT that verifies ownership of the publicKey
    - Parameter publicKey: The public key for which ownership is to be verified
    - Returns: A base64 JWT string
    - Throws: Error if the publicKey is not logged in
     */
    fun jwt(currentUserPublicKey: String): String? {
        // TODO: Check if logged in and throw error if not
        return keyStore.jwt(currentUserPublicKey)
    }
}
