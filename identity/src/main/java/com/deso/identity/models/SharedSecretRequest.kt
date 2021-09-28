package com.deso.identity.models

data class SharedSecretRequest(val ownPublicKey: String, val otherPublicKey: String)
