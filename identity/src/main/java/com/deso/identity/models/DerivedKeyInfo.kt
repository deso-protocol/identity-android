package com.deso.identity.models

import android.net.Uri
import org.json.JSONObject

data class DerivedKeyInfo(
    val publicKey: String,
    val derivedPublicKey: String,
    val derivedSeedHex: String,
    val btcDepositAddress: String,
    val expirationBlock: Int,
    val accessSignature: String,
    val network: String,
    val jwt: String,
    val derivedJwt: String
) {

    fun jsonString() = JSONObject(
        mapOf(
            DerivedKeyInfo::publicKey.name to publicKey,
            DerivedKeyInfo::derivedPublicKey.name to derivedPublicKey,
            DerivedKeyInfo::derivedSeedHex.name to derivedSeedHex,
            DerivedKeyInfo::btcDepositAddress.name to btcDepositAddress,
            DerivedKeyInfo::expirationBlock.name to expirationBlock,
            DerivedKeyInfo::accessSignature.name to accessSignature,
            DerivedKeyInfo::network.name to network,
            DerivedKeyInfo::jwt.name to jwt,
            DerivedKeyInfo::derivedJwt.name to derivedJwt
        )
    ).toString()

    companion object {
        fun fromURI(uri: Uri): DerivedKeyInfo? {
            val publicKey = uri.getQueryParameter(DerivedKeyInfo::publicKey.name)
            val derivedPublicKey = uri.getQueryParameter(DerivedKeyInfo::derivedPublicKey.name)
            val derivedSeedHex = uri.getQueryParameter(DerivedKeyInfo::derivedSeedHex.name)
            val btcDepositAddress = uri.getQueryParameter(DerivedKeyInfo::btcDepositAddress.name)
            val expirationBlock = uri.getQueryParameter(DerivedKeyInfo::expirationBlock.name)
            val accessSignature = uri.getQueryParameter(DerivedKeyInfo::accessSignature.name)
            val network = uri.getQueryParameter(DerivedKeyInfo::network.name)
            val jwt = uri.getQueryParameter(DerivedKeyInfo::jwt.name)
            val derivedJwt = uri.getQueryParameter(DerivedKeyInfo::derivedJwt.name)
            return fromOptionalParameters(
                publicKey,
                derivedPublicKey,
                derivedSeedHex,
                btcDepositAddress,
                Integer.parseInt(expirationBlock ?: "0"),
                accessSignature,
                network,
                jwt,
                derivedJwt
            )
        }

        fun fromJSONString(jsonString: String): DerivedKeyInfo? {
            val json = JSONObject(jsonString)
            val publicKey = json.optString(DerivedKeyInfo::publicKey.name)
            val derivedPublicKey = json.optString(DerivedKeyInfo::derivedPublicKey.name)
            val derivedSeedHex = json.optString(DerivedKeyInfo::derivedSeedHex.name)
            val btcDepositAddress = json.optString(DerivedKeyInfo::btcDepositAddress.name)
            val expirationBlock = json.optInt(DerivedKeyInfo::expirationBlock.name)
            val accessSignature = json.optString(DerivedKeyInfo::accessSignature.name)
            val network = json.optString(DerivedKeyInfo::network.name)
            val jwt = json.optString(DerivedKeyInfo::jwt.name)
            val derivedJwt = json.optString(DerivedKeyInfo::derivedJwt.name)
            return fromOptionalParameters(
                publicKey,
                derivedPublicKey,
                derivedSeedHex,
                btcDepositAddress,
                expirationBlock,
                accessSignature,
                network,
                jwt,
                derivedJwt
            )
        }

        private fun fromOptionalParameters(
            publicKey: String?,
            derivedPublicKey: String?,
            derivedSeedHex: String?,
            btcDepositAddress: String?,
            expirationBlock: Int?,
            accessSignature: String?,
            network: String?,
            jwt: String?,
            derivedJwt: String?
        ): DerivedKeyInfo? {
            return when (publicKey.isNullOrEmpty() ||
                    derivedPublicKey.isNullOrEmpty() ||
                    derivedSeedHex.isNullOrEmpty() ||
                    btcDepositAddress.isNullOrEmpty() ||
                    expirationBlock == null ||
                    accessSignature.isNullOrEmpty() ||
                    network.isNullOrEmpty() ||
                    jwt.isNullOrEmpty() ||
                    derivedJwt.isNullOrEmpty()) {
                true -> null
                false -> DerivedKeyInfo(
                    publicKey,
                    derivedPublicKey,
                    derivedSeedHex,
                    btcDepositAddress,
                    expirationBlock,
                    accessSignature,
                    network,
                    jwt,
                    derivedJwt
                )
            }
        }
    }
}
