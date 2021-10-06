package com.deso.identity.workers

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import com.deso.identity.models.SharedSecretRequest
import kotlin.random.Random

class AuthWorker {

    fun navigateToLogin(context: Context) {
        val uri: Uri = Uri.parse("$IDENTITY_BASE_URL/derive")
            .buildUpon()
            .appendQueryParameter("webview", "true")
            .appendQueryParameter("callback", "${context.packageName}.identity://app")
            .build()
        launchUriInCustomTab(context, uri)
    }

    fun navigateToSignup(context: Context) {
        val uri: Uri = Uri.parse("http://10.0.2.2:3000")
        //TODO: define URL and query params for redirect and state
        launchUriInCustomTab(context, uri)
    }

    fun navigateToSharedSecretRequest(context: Context, requests: List<SharedSecretRequest>) {
        val uri: Uri = Uri.parse("http://10.0.2.2:3000")
        //TODO: define URL and query params for redirect and state
        launchUriInCustomTab(context, uri)
    }

    private fun launchUriInCustomTab(context: Context, uri: Uri) {
        val customTabsIntent = CustomTabsIntent.Builder().build()
        customTabsIntent.intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        customTabsIntent.launchUrl(context, uri)
    }

    companion object {
        const val IDENTITY_BASE_URL = "https://identity.bitclout.com"
    }
}
