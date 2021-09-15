package com.deso.identity.models

data class EncryptedMessagesThread(val publicKey: String, val encryptedMessages: List<String>)
