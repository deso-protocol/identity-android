package com.bitclout.identity.models

import android.net.Uri

data class DerivedKeyInfo(
    val truePublicKey: String,
    val newPublicKey: String,
    val newPrivateKey: String,
    val signedHash: String,
    val jwt: String
) {

    companion object {
        fun fromURI(uri: Uri): DerivedKeyInfo? {
            val truePublicKey = uri.getQueryParameter(DerivedKeyInfo::truePublicKey.name)
            val newPublicKey = uri.getQueryParameter(DerivedKeyInfo::newPublicKey.name)
            val newPrivateKey = uri.getQueryParameter(DerivedKeyInfo::newPrivateKey.name)
            val signedHash = uri.getQueryParameter(DerivedKeyInfo::signedHash.name)
            val jwt = uri.getQueryParameter(DerivedKeyInfo::jwt.name)
            return fromOptionalParameters(
                truePublicKey,
                newPublicKey,
                newPrivateKey,
                signedHash,
                jwt
            )
        }

        fun fromOptionalParameters(
            truePublicKey: String?,
            newPublicKey: String?,
            newPrivateKey: String?,
            signedHash: String?,
            jwt: String?
        ): DerivedKeyInfo? {
            return when (truePublicKey.isNullOrEmpty() ||
                    newPublicKey.isNullOrEmpty() ||
                    newPrivateKey.isNullOrEmpty() ||
                    signedHash.isNullOrEmpty() ||
                    jwt.isNullOrEmpty()) {
                true -> null
                false -> DerivedKeyInfo(truePublicKey, newPublicKey, newPrivateKey, signedHash, jwt)
            }
        }
    }
}