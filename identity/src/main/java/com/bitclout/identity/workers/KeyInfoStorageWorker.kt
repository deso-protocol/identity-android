package com.bitclout.identity.workers

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.bitclout.identity.models.DerivedKeyInfo

class KeyInfoStorageWorker constructor(applicationContext: Context) {

    private val mainKey = MasterKey.Builder(applicationContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    private val sharedPreferences: SharedPreferences = EncryptedSharedPreferences.create(
        applicationContext,
        PREF_FILE_NAME,
        mainKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveDerivedKeyInfo(derivedKeyInfo: DerivedKeyInfo) {
        with(sharedPreferences.edit()) {
            putString(TRUE_PUBLIC_KEY, derivedKeyInfo.truePublicKey)
            putString(NEW_PUBLIC_KEY, derivedKeyInfo.newPublicKey)
            putString(NEW_PRIVATE_KEY, derivedKeyInfo.newPrivateKey)
            putString(SIGNED_HASH, derivedKeyInfo.signedHash)
            putString(JWT, derivedKeyInfo.jwt)
            apply()
        }
    }

    fun loadDerivedKeyInfo(): DerivedKeyInfo? {
        with(sharedPreferences) {
            return DerivedKeyInfo.fromOptionalParameters(
                getString(TRUE_PUBLIC_KEY, null),
                getString(NEW_PUBLIC_KEY, null),
                getString(NEW_PRIVATE_KEY, null),
                getString(SIGNED_HASH, null),
                getString(JWT, null)
            )
        }
    }

    companion object {
        internal const val PREF_FILE_NAME = "bitclout_identity_pref_file"

        internal const val TRUE_PUBLIC_KEY = "TRUE_PUBLIC_KEY"
        internal const val NEW_PUBLIC_KEY = "NEW_PUBLIC_KEY"
        internal const val NEW_PRIVATE_KEY = "NEW_PRIVATE_KEY"
        internal const val SIGNED_HASH = "SIGNED_HASH"
        internal const val JWT = "JWT"
    }
}
