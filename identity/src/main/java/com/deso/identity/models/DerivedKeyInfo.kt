package com.deso.identity.models

import android.net.Uri
import org.json.JSONObject

data class DerivedKeyInfo(
    val truePublicKey: String,
    val newPublicKey: String,
    val newPrivateKey: String,
    val signedHash: String,
    val jwt: String
) {

    fun jsonString() = JSONObject(
        mapOf(
            DerivedKeyInfo::truePublicKey.name to truePublicKey,
            DerivedKeyInfo::newPublicKey.name to newPublicKey,
            DerivedKeyInfo::newPrivateKey.name to newPrivateKey,
            DerivedKeyInfo::signedHash.name to signedHash,
            DerivedKeyInfo::jwt.name to jwt
        )
    ).toString()

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

        fun fromJSONString(jsonString: String): DerivedKeyInfo? {
            val json = JSONObject(jsonString)
            val truePublicKey = json.optString(DerivedKeyInfo::truePublicKey.name)
            val newPublicKey = json.optString(DerivedKeyInfo::newPublicKey.name)
            val newPrivateKey = json.optString(DerivedKeyInfo::newPrivateKey.name)
            val signedHash = json.optString(DerivedKeyInfo::signedHash.name)
            val jwt = json.optString(DerivedKeyInfo::jwt.name)
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
