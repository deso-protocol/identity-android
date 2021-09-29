package com.deso.identity.workers

import com.deso.identity.models.IdentityException
import com.deso.identity.workers.crypto.ECIES

class TransactionSigner(private val keyStore: KeyInfoStorageWorker, val ecies: ECIES) {

    fun signTransaction(currentUserPublicKey: String, transactionHex: String): String {
        val derivedKeyInfo = keyStore.loadDerivedKeyInfo(currentUserPublicKey)
            ?: throw IdentityException.NotLoggedInException()
        return ecies.signTransaction(derivedKeyInfo.derivedSeedHex, transactionHex)
    }
}
