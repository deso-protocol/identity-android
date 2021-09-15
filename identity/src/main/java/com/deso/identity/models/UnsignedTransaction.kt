package com.deso.identity.models

data class UnsignedTransaction(
    val publicKey: String,
    val transactionHex: String
)
