package com.deso.identity.workers

import com.deso.identity.models.UnsignedTransaction

class TransactionSigner {

    fun signTransaction(transaction: UnsignedTransaction): String {
        // TODO: Actually sign the transaction and return the signed hash
        /*
         * 1. Check the public key being used to create the transaction
         * 2. Check if key info is stored for that public key
         *      a. If not, throw an error
         * 3. Check if the stored key data is still valid to sign the transaction
         *      a. If not, present re-auth UI and retry when complete
         * 4. Sign the transaction
         * 5. Return the signed hash
         */
        return ""
    }
}
