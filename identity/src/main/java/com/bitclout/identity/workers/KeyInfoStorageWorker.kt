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
            putString(derivedKeyInfo.truePublicKey, derivedKeyInfo.jsonString())
            apply()
        }
    }

    fun removeDerivedKeyInfo(truePublicKey: String) {
        with(sharedPreferences.edit()) {
            remove(truePublicKey)
            apply()
        }
    }

    fun loadDerivedKeyInfo(truePublicKey: String): DerivedKeyInfo? {
        with(sharedPreferences) {
            val jsonString = getString(truePublicKey, null)
            return jsonString?.let { DerivedKeyInfo.fromJSONString(it) }
        }
    }

    fun setStoredKeys(publicKeys: List<String>) = sharedPreferences.edit().putStringSet(PUBLIC_KEYS, publicKeys.toSet()).apply()

    fun getAllStoredKeys(): List<String> = sharedPreferences.getStringSet(PUBLIC_KEYS, emptySet())?.toList() ?: emptyList()

    fun clearAllStoredInfo() = sharedPreferences.edit().clear().apply()

    companion object {
        internal const val PREF_FILE_NAME = "bitclout_identity_pref_file"

        internal const val PUBLIC_KEYS = "PUBLIC_KEYS"
    }
}
