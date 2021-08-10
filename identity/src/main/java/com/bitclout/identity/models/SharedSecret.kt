package com.bitclout.identity.models

data class SharedSecret(
    val secret: String,
    val privateKey: String,
    val publicKey: String,
    val myTruePublicKey: String
)
