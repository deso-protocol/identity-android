package com.bitclout.identity.models

import java.lang.Exception

sealed class IdentityException : Exception() {
    class MissingPresentationAnchorException : IdentityException()
    class NotLoggedInException : IdentityException()
    class MissingInfoForPublicKeyException : IdentityException()
    class KeyInfoExpiredException : IdentityException()
    class MissingSharedSecretException : IdentityException()
}

sealed class CryptoException : Exception() {
    class BadPrivateKeyException : CryptoException()
    class BadPublicKeyException : CryptoException()
    class BadSignatureException : CryptoException()
    class CouldNotGetPublicKeyException : CryptoException()
    class EmptyMessageException : CryptoException()
    class MessageTooLongException : CryptoException()
    class CouldNotGenerateRandomBytesException : CryptoException()
    class InvalidCipherTextException : CryptoException()
    class IncorrectMACException : CryptoException()
}

