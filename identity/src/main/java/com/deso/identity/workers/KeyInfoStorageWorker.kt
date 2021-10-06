package com.deso.identity.workers

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.deso.identity.Identity
import com.deso.identity.models.DerivedKeyInfo
import com.deso.identity.models.SharedSecret
import org.json.JSONArray
import org.json.JSONException
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets


class KeyInfoStorageWorker constructor(private val applicationContext: Context) {

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
            putString(derivedKeyInfo.publicKey, derivedKeyInfo.jsonString())
            apply()
        }
        val existingKeys = getAllStoredKeys()
        setStoredKeys(existingKeys.plus(derivedKeyInfo.publicKey))
    }

    fun removeDerivedKeyInfo(truePublicKey: String) {
        with(sharedPreferences.edit()) {
            remove(truePublicKey)
            apply()
        }
        setStoredKeys(Identity.getLoggedInKeys().filterNot { it == truePublicKey })
    }

    fun loadDerivedKeyInfo(truePublicKey: String): DerivedKeyInfo? {
        with(sharedPreferences) {
            val jsonString = getString(truePublicKey, null)
            return jsonString?.let { DerivedKeyInfo.fromJSONString(it) }
        }
    }

    private fun setStoredKeys(publicKeys: List<String>) =
        sharedPreferences.edit().putStringSet(PUBLIC_KEYS, publicKeys.toSet()).apply()

    fun getAllStoredKeys(): List<String> =
        sharedPreferences.getStringSet(PUBLIC_KEYS, emptySet())?.toList() ?: emptyList()

    fun clearAllStoredInfo() = sharedPreferences.edit().clear().apply()

    fun jwt(publicKey: String): String? = loadDerivedKeyInfo(publicKey)?.jwt

    fun getSharedSecrets(): List<SharedSecret> {
        val currentSharedSecretsString: String = readFromFile()
        return try {
            val results = mutableListOf<SharedSecret?>()
            val rawArray = JSONArray(currentSharedSecretsString)
            for (i in 0 until rawArray.length()) {
                results.add(SharedSecret.fromJSONString(rawArray.getString(i)))
            }
            results.filterNotNull()
        } catch (exception: JSONException) {
            emptyList()
        }
    }

    fun saveSharedSecrets(secrets: List<SharedSecret>) {
        val currentSharedSecrets = getSharedSecrets()
        val serialisedSharedSecrets = JSONArray(
            (secrets + currentSharedSecrets)
                .distinctBy { it.ownPublicKey + it.otherPublicKey }
                .map { it.jsonObject() }
        ).toString()
        writeToFile(serialisedSharedSecrets)
    }

    private fun readFromFile(): String {
        val encryptedFile = getEncryptedFile()
        val inputStream = encryptedFile.openFileInput()
        val byteArrayOutputStream = ByteArrayOutputStream()
        var nextByte: Int = inputStream.read()
        while (nextByte != -1) {
            byteArrayOutputStream.write(nextByte)
            nextByte = inputStream.read()
        }
        return byteArrayOutputStream.toByteArray().toString(StandardCharsets.UTF_8)
    }

    private fun writeToFile(serialisedSharedSecrets: String) {
        val encryptedFile = getEncryptedFile()
        val fileContent = serialisedSharedSecrets.toByteArray(StandardCharsets.UTF_8)
        encryptedFile.openFileOutput().apply {
            write(fileContent)
            flush()
            close()
        }
    }

    private fun getEncryptedFile(): EncryptedFile {
        return EncryptedFile.Builder(
            applicationContext,
            File(DIRECTORY, FILE_NAME),
            mainKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
    }

    companion object {
        internal const val PREF_FILE_NAME = "deso_identity_pref_file"

        internal const val PUBLIC_KEYS = "PUBLIC_KEYS"
        internal const val DIRECTORY = "deso_identity"
        internal const val FILE_NAME = "deso_identity_secrets.txt"
    }
}
