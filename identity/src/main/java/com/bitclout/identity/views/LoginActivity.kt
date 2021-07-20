package com.bitclout.identity.views

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import com.bitclout.identity.Identity
import com.bitclout.identity.R
import com.bitclout.identity.databinding.ActivityLoginBinding
import com.bitclout.identity.models.DerivedKeyInfo
import com.bitclout.identity.workers.KeyInfoStorageWorker

class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)
        intent?.data?.let { handleLogin(it) }
//        binding.loginButton.setOnClickListener { openIdentityCustomTabForLogin() }
    }

    private fun handleLogin(loginResponseUri: Uri) {
        Log.d("Handle login", "Returned Uri: $loginResponseUri")
        //TODO: handle multiple accounts coming back once we have the correct URI structure
        DerivedKeyInfo.fromURI(loginResponseUri)?.let {
            Identity.keyStore.saveDerivedKeyInfo(it)
            Identity.keyStore.setStoredKeys(listOf(it.truePublicKey))
            Log.d("Saved derived key info", "Closing LoginActivity")
            finish()
        }
    }

    private fun openIdentityCustomTabForLogin() {
        val uri: Uri = Uri.parse("http://10.0.2.2:3000")
        //TODO: do we need to send any data to web app?
//            .buildUpon()
//            .appendQueryParameter("redirect_uri", redirectUri)
//            .build()

        val customTabsIntent = CustomTabsIntent.Builder().build()
        customTabsIntent.intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        customTabsIntent.launchUrl(this, uri)
    }

    companion object {
        fun startIntent(context: Context) = Intent(context, LoginActivity::class.java)
    }
}