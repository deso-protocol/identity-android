package com.deso.identity.models

import org.json.JSONObject

data class SharedSecret(
    val secret: String,
    val ownPublicKey: String,
    val otherPublicKey: String
) {
    fun jsonObject() = JSONObject(
        mapOf(
            ::secret.name to secret,
            ::ownPublicKey.name to ownPublicKey,
            ::otherPublicKey.name to otherPublicKey
        )
    )

    companion object {
        fun fromJSONString(jsonString: String): SharedSecret? {
            val json = JSONObject(jsonString)
            val secret = json.optString(SharedSecret::secret.name)
            val ownPublicKey = json.optString(SharedSecret::ownPublicKey.name)
            val otherPublicKey = json.optString(SharedSecret::otherPublicKey.name)
            return fromOptionalParameters(
                secret,
                ownPublicKey,
                otherPublicKey
            )
        }

        private fun fromOptionalParameters(
            secret: String?,
            ownPublicKey: String?,
            otherPublicKey: String?
        ): SharedSecret? {
            return when (secret.isNullOrEmpty() ||
                    ownPublicKey.isNullOrEmpty() ||
                    otherPublicKey.isNullOrEmpty()) {
                true -> null
                false -> SharedSecret(secret, ownPublicKey, otherPublicKey)
            }
        }
    }
}
