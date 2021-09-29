package com.deso.identity.views

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.deso.identity.Identity
import com.deso.identity.R
import com.deso.identity.databinding.ActivityWebAppHandlerBinding
import com.deso.identity.models.DerivedKeyInfo

class WebAppHandlerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityWebAppHandlerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_web_app_handler)
        binding = ActivityWebAppHandlerBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)
        intent?.data?.let { handleWebAppResponse(it) }
    }

    private fun handleWebAppResponse(responseUri: Uri) {
        Log.d("Handle web app response", "Returned Uri: $responseUri")
        //TODO check outgoing state value against return
        // split on path for login, signup and shared secrets
        DerivedKeyInfo.fromURI(responseUri)?.let {
            Identity.keyStore.saveDerivedKeyInfo(it)
            Identity.keyStore.setStoredKeys(listOf(it.publicKey))
            Log.d("Saved derived key info", "Closing WebAppHandlerActivity")
            finish()
        }
    }

    companion object {
        fun startIntent(context: Context) = Intent(context, WebAppHandlerActivity::class.java)
    }
}