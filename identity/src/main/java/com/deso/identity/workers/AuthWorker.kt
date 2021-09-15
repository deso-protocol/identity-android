package com.deso.identity.workers

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.deso.identity.models.DerivedKeyInfo
import com.deso.identity.views.LoginActivity

class AuthWorker {

    fun navigateToLogin(context: Context) {
        val uri: Uri = Uri.parse("http://10.0.2.2:3000")
        //TODO: do we need to send any data to web app?
//            .buildUpon()
//            .appendQueryParameter("redirect_uri", redirectUri)
//            .build()
        val customTabsIntent = CustomTabsIntent.Builder().build()
        customTabsIntent.intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        customTabsIntent.launchUrl(context, uri)
    }
}
